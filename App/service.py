def key_to_hex_str(key: str) -> str:
    return '0x' + key.encode('utf-8').hex()