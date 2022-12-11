#!/usr/local/bin/python
import sys
from typing import Hashable, Union, TypedDict

import ovh
import yaml
from tap import Tap


class Arguments(Tap):
    credentials: str

    def configure(self) -> None:
        self.add_argument("credentials")


class OvhConsumerKeyRequest(TypedDict):
    validationUrl: str
    consumerKey: str


def main() -> int:
    args = Arguments().parse_args()

    with open(args.credentials, "r", encoding="utf-8") as file:
        ovh_config: dict[Hashable, Union[dict[Hashable, str], int]] = yaml.load(
            file, Loader=yaml.Loader
        )
    ovh_client: ovh.Client = ovh.Client(
        endpoint=ovh_config["ovh"]["auth_entrypoint"],
        application_key=ovh_config["ovh"]["auth_application_key"],
        application_secret=ovh_config["ovh"]["auth_application_secret"],
    )

    consumer_key = ovh_client.new_consumer_key_request()
    consumer_key.add_rules(["GET", "PUT", "POST", "DELETE"], "/domain/zone/*")

    consumer_key_request: OvhConsumerKeyRequest = consumer_key.request()
    print("Validation URL: " + consumer_key_request["validationUrl"])
    ovh_config["ovh"]["dns_ovh_consumer_key"] = consumer_key_request["consumerKey"]

    with open(args.credentials, "w", encoding="utf-8") as file:
        yaml.dump(file, Dumper=yaml.Dumper)
    return 0


if __name__ == "__main__":
    sys.exit(main())
