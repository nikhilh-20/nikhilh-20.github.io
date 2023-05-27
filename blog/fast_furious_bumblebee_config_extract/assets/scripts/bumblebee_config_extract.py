# Mostly taken from https://blog.krakz.fr/articles/bumblebee
# Minor additions by @ka1do9
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ARC4


def decrypt_rc4(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt RC4 encrypt data, `pip install cryptography`"""

    algorithm = ARC4(key)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    cleartext = decryptor.update(ciphertext)

    return cleartext


def get_bumblebee_c2(data: bytes) -> bytes:
    """
    Command and Control are stored at the end of the .data section,
    the configuration of the obfuscated C2 and its associated RC4
    are stored in the same blob with a fixed length of
    4105 plus one null byte (4106).
    !\xac\xd2\xfe=;\x87\x94\xebP\x8e@\x08}\x00/^I\xd4\x86\xaf\xd2\x14-
    \x16\x89A\xa9uT\x00\xbduC\xb7\x9e~\x19\xac\x9f\xb4\x0f\xae>\xcc
    \x96S]\xb56\x93C\x9d*p\xed\xc9\x04:Oew\xc3*X`:a\xe0T\x8e\x93>\xf9
    \xf8\xe2\x17Q\x15b,8\xa8[\xf5N\x93\xffMM]\x8d\xec\xde\x13\x95z\xc3
    ...
    ...
    ... <redatacted> ...
    \xd4\x00\xa1xZ:\x1e\x90\x00X\xea\xca\x0c\'\xee\xffOR5tw\xc0I\x86R"!
    \xf8\xa3\x87\xc8\x16Mo_5\x82_\x81\x9f<RC4 key composed by 10 bytes>

    The campaign ID is beyond the key. There are other bytes following
    the key and then comes the campaign ID, so I extract a total of 179
    contiguous non-zero bytes, skip over the first 80 bytes (decrypts to
    b"443". Encrypted bytes related to campaign ID follow which are then
    decrypted.
    """
    c2 = b""
    campaign_id = b""
    key = None

    for blob in map(lambda x: x.strip(b"\x00"), data.split(b"\x00" * 4)):
        if len(blob) == 4106:
            key = blob[-10:]
            ciphertext = blob[:-10]
            c2 = decrypt_rc4(key, ciphertext)
            c2 = c2.replace(b"\x00", b"")
            print(f"BumbleBee Command and Control IoCs: {c2}")
        # Addition from @ka1do9
        elif len(blob) == 179 and key:
            campaign_id = decrypt_rc4(key, blob[80:80+79]).replace(b"\x00", b"")
            print(f"Campaign ID: {campaign_id}")

    return c2, campaign_id


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
      get_bumblebee_c2(f.read())
