PROTOCOL_VERSION = "1.1.0"
PROTOCOL_MAJOR = PROTOCOL_VERSION.split(".", 1)[0]


def compatible(peer_version: str) -> bool:
    return peer_version.split(".", 1)[0] == PROTOCOL_MAJOR
