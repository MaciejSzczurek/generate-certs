#!/usr/local/bin/python

import importlib
import sys
from datetime import datetime, timedelta, timezone
from os import remove, rename, chmod, path
from os.path import exists
from shutil import copy, chown
from subprocess import run
from typing import Union, List, Optional, Tuple, Type, cast, Final

import docker
from certbot.main import main as certbot
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import CertificateSigningRequest
from docker import DockerClient
from docker.errors import NotFound
from docker.models.containers import Container
from lexicon.config import ConfigResolver
from lexicon.interfaces import Provider
from tap import Tap

FULL_CHAIN_RSA_PEM: Final = "full_chain-rsa.pem"
FULL_CHAIN_PEM: Final = "full_chain.pem"
NEW_REQ_RSA_PEM: Final = "new-req-rsa.pem"
NEW_KEY_RSA_PEM: Final = "new-key-rsa.pem"
ZERO_CERT_PEM: Final = "0000_cert.pem"
NEW_REQ_PEM: Final = "new-req.pem"
NEW_KEY_PEM: Final = "new-key.pem"
KEY_RSA_PEM: Final = "key-rsa.pem"
KEY_PEM: Final = "key.pem"
CHAIN_RSA_PEM: Final = "chain-rsa.pem"
CHAIN_PEM: Final = "chain.pem"
CERT_RSA_PEM: Final = "cert-rsa.pem"
CERT_PEM: Final = "cert.pem"


class Arguments(Tap):
    options: str
    domains: List[str]
    days: int = 14
    test_cert: bool = False
    restart_nginx: bool = False
    reset_files: bool = False
    lemp_path: str = "/opt/lemp"
    nginx_container: str = "lemp-nginx-1"
    mailcow_path: Optional[str] = None
    mailcow_domain: Optional[str] = None
    mailcow_subdomain: Optional[str] = None
    keycloak_path: Optional[str] = None
    regenerate_tlsa: bool = False
    without_rsa: bool = False
    owner_id: Optional[int] = None

    def configure(self) -> None:
        self.add_argument("options", help="dns-lexicon options file")
        self.add_argument(
            "domains", nargs="+", help="List of domains to obtain a certificate for"
        )
        self.add_argument(
            "--days",
            default=14,
            type=int,
            help="Number of days before a new certificate will be generated",
        )
        self.add_argument(
            "--test-cert",
            default=False,
            type=bool,
            help="Obtain a test certificate from a staging server",
        )
        self.add_argument(
            "--restart-nginx",
            default=False,
            type=bool,
            help="Restart nginx after obtaining certificate",
        )
        self.add_argument(
            "--reset-files",
            default=False,
            type=bool,
            help="Recover certificate files from backup",
        )
        self.add_argument(
            "--lemp-path",
            default="/opt/lemp",
            type=str,
            help="Location for Docker Lemp",
        )
        self.add_argument(
            "--nginx-container",
            default="lemp-nginx-1",
            type=str,
            help="Nginx container name",
        )
        self.add_argument(
            "--mailcow-path", default=None, type=str, help="Location of mailcow files"
        )
        self.add_argument(
            "--mailcow-domain",
            default=None,
            type=str,
            help="The main domain used in mailcow.",
        )
        self.add_argument(
            "--mailcow-subdomain",
            default=None,
            type=str,
            help="The main subdomain used in mailcow",
        )
        self.add_argument(
            "--keycloak-path", default=None, type=str, help="Location of keycloak path"
        )
        self.add_argument(
            "--regenerate-tlsa",
            default=False,
            type=bool,
            help="Generate and add certificate keys to the dns server",
        )
        self.add_argument(
            "--without-rsa",
            default=False,
            type=bool,
            help="Don't create rsa certificates",
        )
        self.add_argument(
            "--owner-id", default=None, type=int, help="Owner UID for certificate file"
        )


class MailcowException(Exception):
    pass


args = Arguments().parse_args()


def move(src: str, dst: str) -> None:
    if exists(src):
        rename(src, dst)
        chmod(dst, 0o600)


def create_dns_client() -> Provider:
    config_resolver = (
        ConfigResolver().with_config_file(args.options).with_dict({"ttl": 0})
    )

    provider_class: Type[Provider] = getattr(
        importlib.import_module(
            f"lexicon._private.providers.{config_resolver.resolve('provider_name')}"
        ),
        "Provider",
    )

    provider = provider_class(config_resolver)
    provider.domain = args.mailcow_domain
    provider.authenticate()

    return provider


def generate_tlsa() -> None:
    def generate_domain_name(port: int) -> str:
        return f"_{str(port)}._tcp.{args.mailcow_subdomain}.{args.mailcow_domain}"

    def get_digest(filename: str) -> str:
        with open(filename, "rb") as file:
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(
                x509.load_pem_x509_certificate(file.read(), default_backend())
                .public_key()
                .public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

            return digest.finalize().hex()

    dns_client = create_dns_client()

    ca_dgst = get_digest(CHAIN_PEM)
    ec_dgst = get_digest(FULL_CHAIN_PEM)

    for record in dns_client.list_records("TLSA"):
        if record["name"].endswith(
            f"._tcp.{args.mailcow_subdomain}.{args.mailcow_domain}"
        ):
            dns_client.delete_record(rtype="TLSA", name=record["name"])

    dns_client.create_record(
        "TLSA", generate_domain_name(25), f"3 1 1 {get_digest(FULL_CHAIN_RSA_PEM)}"
    )

    for port in [25, 110, 143, 465, 587, 993, 995, 4190]:
        domain_name = generate_domain_name(port)
        dns_client.create_record("TLSA", domain_name, f"2 1 1 {ca_dgst}")
        dns_client.create_record("TLSA", domain_name, f"3 1 1 {ec_dgst}")


def check_mailcow() -> None:
    if not exists(args.options):
        raise MailcowException("Credentials file is not exists")

    if args.mailcow_path and (not args.mailcow_domain or not args.mailcow_subdomain):
        raise MailcowException("Mailcow domain and subdomain are required.")


def generate_sign_request(
    key: Union[EllipticCurvePrivateKey, RSAPrivateKey]
) -> CertificateSigningRequest:
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, args.domains[0])])
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(domain) for domain in args.domains]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA512(), default_backend())
    )


def write_key(
    filename: str, key: Union[EllipticCurvePrivateKey, RSAPrivateKey]
) -> None:
    with open(filename, "wb") as file:
        file.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    chmod(filename, 0o600)


def write_req(filename: str, csr: CertificateSigningRequest) -> None:
    with open(filename, "wb") as file:
        file.write(csr.public_bytes(serialization.Encoding.PEM))
    chmod(filename, 0o600)


def main() -> int:
    if not exists(args.options):
        print("Credentials file is not exists")
        return -1

    if exists(FULL_CHAIN_PEM):
        with open(FULL_CHAIN_PEM, "rb") as file:
            valid_until = x509.load_pem_x509_certificate(
                file.read(), default_backend()
            ).not_valid_after_utc - timedelta(days=args.days)
    else:
        valid_until = datetime.now(timezone.utc) - timedelta(days=1)

    if args.regenerate_tlsa:
        try:
            check_mailcow()
        except MailcowException as exception:
            print(exception)
            return -1
        generate_tlsa()
        return 0

    if args.reset_files:
        move("cert.old.pem", CERT_PEM)
        move("cert-rsa.old.pem", CERT_RSA_PEM)
        move("chain.old.pem", CHAIN_PEM)
        move("chain-rsa.old.pem", CHAIN_RSA_PEM)
        move("full_chain.old.pem", FULL_CHAIN_PEM)
        move("full_chain-rsa.old.pem", FULL_CHAIN_RSA_PEM)
        move("key.old.pem", KEY_PEM)
        move("key-rsa.old.pem", KEY_RSA_PEM)
        return 0

    if valid_until <= datetime.now(timezone.utc):
        try:
            check_mailcow()
        except MailcowException as exception:
            print(exception)
            return -1

        key: EllipticCurvePrivateKey = ec.generate_private_key(
            curve=ec.SECP256R1(), backend=default_backend()
        )
        write_key(NEW_KEY_PEM, key)
        write_req(NEW_REQ_PEM, generate_sign_request(key))

        command: List[str] = [
            "certonly",
            "--non-interactive",
            "--authenticator",
            "dns-lexicon",
            "--dns-lexicon-options",
            args.options,
            "--csr",
            NEW_REQ_PEM,
        ]

        if args.test_cert:
            command.append("--test-cert")

        certbot(command)

        if exists(ZERO_CERT_PEM):
            move(KEY_PEM, "key.old.pem")
            move(CERT_PEM, "cert.old.pem")
            move(CHAIN_PEM, "chain.old.pem")
            move(FULL_CHAIN_PEM, "full_chain.old.pem")
            move(NEW_KEY_PEM, KEY_PEM)
            remove(NEW_REQ_PEM)
            move(ZERO_CERT_PEM, CERT_PEM)
            move("0000_chain.pem", CHAIN_PEM)
            move("0001_chain.pem", FULL_CHAIN_PEM)
            if args.owner_id:
                for file in {CERT_PEM, CHAIN_PEM, FULL_CHAIN_PEM, KEY_PEM}:
                    chown(file, args.owner_id)
        else:
            remove(NEW_KEY_PEM)
            remove(NEW_REQ_PEM)
            return -1

        if not args.without_rsa:
            key: RSAPrivateKey = rsa.generate_private_key(
                key_size=2048, public_exponent=65537, backend=default_backend()
            )
            write_key(NEW_KEY_RSA_PEM, key)
            write_req(NEW_REQ_RSA_PEM, generate_sign_request(key))

            command: List[str] = [
                "certonly",
                "--non-interactive",
                "--authenticator",
                "dns-lexicon",
                "--dns-lexicon-options",
                args.options,
                "--csr",
                NEW_REQ_RSA_PEM,
            ]

            if args.test_cert:
                command.append("--test-cert")

            certbot(command)

            if exists(ZERO_CERT_PEM):
                move(KEY_RSA_PEM, "key-rsa.old.pem")
                move(CERT_RSA_PEM, "cert-rsa.old.pem")
                move(CHAIN_RSA_PEM, "chain-rsa.old.pem")
                move(FULL_CHAIN_RSA_PEM, "full_chain-rsa.old.pem")
                move(NEW_KEY_RSA_PEM, KEY_RSA_PEM)
                remove(NEW_REQ_RSA_PEM)
                move(ZERO_CERT_PEM, CERT_RSA_PEM)
                move("0000_chain.pem", CHAIN_RSA_PEM)
                move("0001_chain.pem", FULL_CHAIN_RSA_PEM)
                if args.owner_id:
                    for file in {CERT_RSA_PEM, CHAIN_RSA_PEM, FULL_CHAIN_RSA_PEM, KEY_RSA_PEM}:
                        chown(file, args.owner_id)
            else:
                remove(NEW_KEY_RSA_PEM)
                remove(NEW_REQ_RSA_PEM)
                return -1

        if args.mailcow_path or args.restart_nginx or args.keycloak_path:
            docker_client: DockerClient = docker.from_env()

            if args.mailcow_path:
                if not args.test_cert:
                    copy(
                        FULL_CHAIN_PEM,
                        path.join(args.mailcow_path, "data/assets/ssl/cert.pem"),
                    )
                    copy(
                        FULL_CHAIN_RSA_PEM,
                        path.join(args.mailcow_path, "data/assets/ssl/cert-rsa.pem"),
                    )
                    copy(
                        KEY_PEM, path.join(args.mailcow_path, "data/assets/ssl/key.pem")
                    )
                    copy(
                        KEY_RSA_PEM,
                        path.join(args.mailcow_path, "data/assets/ssl/key-rsa.pem"),
                    )
                    copy(
                        CHAIN_PEM,
                        path.join(args.mailcow_path, "data/assets/ssl/chain.pem"),
                    )

                    generate_tlsa()

                mailcow_containers: List[Tuple[str, str]] = [
                    ("postfix-mailcow", "postfix reload"),
                    ("nginx-mailcow", "nginx -s reload"),
                    ("dovecot-mailcow", "dovecot reload"),
                ]

                for (name, command) in mailcow_containers:
                    containers_list = docker_client.containers.list(
                        filters={"name": name}
                    )

                    if len(containers_list) > 0:
                        containers_list[0].exec_run(command)

            if args.restart_nginx:
                try:
                    cast(
                        Container, docker_client.containers.get(args.nginx_container)
                    ).exec_run("nginx -s reload")
                except NotFound:
                    pass

            if args.keycloak_path:
                run(
                    [
                        "docker",
                        "compose",
                        "-f",
                        path.join(args.lemp_path, "docker-compose.yaml"),
                        "stop",
                        "keycloak",
                    ],
                    check=True,
                )

                keycloak_full_chain_pem = path.join(args.keycloak_path, FULL_CHAIN_PEM)
                keycloak_key_pem = path.join(args.keycloak_path, KEY_PEM)

                copy(FULL_CHAIN_PEM, keycloak_full_chain_pem)
                copy(KEY_PEM, keycloak_key_pem)

                chown(keycloak_full_chain_pem, user=1000)
                chown(keycloak_key_pem, user=1000)

                chmod(keycloak_full_chain_pem, 0o640)
                chmod(keycloak_key_pem, 0o640)

                run(
                    [
                        "docker",
                        "compose",
                        "-f",
                        path.join(args.lemp_path, "docker-compose.yaml"),
                        "up",
                        "-d",
                        "keycloak",
                    ],
                    check=True,
                )
    return 0

if __name__ == "__main__":
    sys.exit(main())
