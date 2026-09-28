import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reverse_lab.corpus import write_manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="artifacts/local-corpus-manifest.json")
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    manifest = write_manifest([Path(item) for item in args.paths], args.output)
    print(f"manifest={args.output}")
    print(f"files={len(manifest['files'])}")


if __name__ == "__main__":
    main()
