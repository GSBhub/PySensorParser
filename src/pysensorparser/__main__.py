import argparse
import logging
import sys

from . import parse_rom


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Find call-hub functions in M7700 ECU binaries."
    )
    parser.add_argument("files", nargs="+", metavar="FILE", help="M7700 ROM file(s)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)

    for path in args.files:
        print(f"\nOpening: {path}")
        callers = parse_rom(path)
        for addr, caller in sorted(callers.items()):
            print(f"  0x{addr:04x}  ({caller.count} call sites)")


if __name__ == "__main__":
    main()
