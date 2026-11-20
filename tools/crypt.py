#!/usr/bin/env python3
"""Совместимый с Mini App инструмент командной строки (pip install pynacl).

  python crypt.py keygen
  python crypt.py encrypt <открытый_ключ>  [текст]
  python crypt.py decrypt <закрытый_ключ>  [шифротекст]

Если текст или шифротекст не указан, он читается со стандартного ввода.
Пробелы и переносы строк внутри ключей и шифротекста игнорируются.
"""
import base64
import binascii
import sys

from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox


def b64(value: str, what: str) -> bytes:
    clean = "".join(value.split())
    try:
        return base64.b64decode(clean, validate=True)
    except (binascii.Error, ValueError):
        sys.exit(f"Ошибка: {what} не похож на base64 (проверьте, что скопирован целиком; '=' бывает только в конце).")


def key32(value: str, what: str) -> bytes:
    raw = b64(value, what)
    if len(raw) != 32:
        sys.exit(f"Ошибка: {what} должен быть 32 байта (44 символа base64), а здесь {len(raw)}.")
    return raw


def output_text(data: bytes) -> None:
    if sys.stdout.isatty():
        print(data.decode("utf-8", errors="replace"))
    else:
        sys.stdout.buffer.write(data)


def main() -> None:
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    cmd, rest = args[0], args[1:]

    if cmd == "keygen" and not rest:
        sk = PrivateKey.generate()
        print("private:", base64.b64encode(bytes(sk)).decode())
        print("public: ", base64.b64encode(bytes(sk.public_key)).decode())

    elif cmd == "encrypt" and rest:
        box = SealedBox(PublicKey(key32(rest[0], "открытый ключ")))
        data = " ".join(rest[1:]).encode("utf-8") if len(rest) > 1 else sys.stdin.buffer.read()
        print(base64.b64encode(box.encrypt(data)).decode())

    elif cmd == "decrypt" and rest:
        box = SealedBox(PrivateKey(key32(rest[0], "закрытый ключ")))
        ct_text = "".join(rest[1:]) if len(rest) > 1 else sys.stdin.read()
        try:
            output_text(box.decrypt(b64(ct_text, "шифротекст")))
        except CryptoError:
            sys.exit("Ошибка: не расшифровалось. Либо ключ не от той пары, либо шифротекст повреждён.")

    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
