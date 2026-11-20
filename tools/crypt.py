#!/usr/bin/env python3
"""Совместимый с Mini App инструмент командной строки (pip install pynacl).

  python crypt.py keygen
  python crypt.py encrypt <открытый_ключ_b64>  < текст
  python crypt.py decrypt <закрытый_ключ_b64>  < шифротекст_b64
"""
import base64
import sys

from nacl.public import PrivateKey, PublicKey, SealedBox


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "keygen":
        sk = PrivateKey.generate()
        print("private:", base64.b64encode(bytes(sk)).decode())
        print("public: ", base64.b64encode(bytes(sk.public_key)).decode())
    elif cmd == "encrypt" and len(sys.argv) == 3:
        box = SealedBox(PublicKey(base64.b64decode(sys.argv[2])))
        data = sys.stdin.buffer.read()
        print(base64.b64encode(box.encrypt(data)).decode())
    elif cmd == "decrypt" and len(sys.argv) == 3:
        box = SealedBox(PrivateKey(base64.b64decode(sys.argv[2])))
        ct = base64.b64decode("".join(sys.stdin.read().split()))
        sys.stdout.buffer.write(box.decrypt(ct))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
