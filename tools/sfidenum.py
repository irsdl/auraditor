#!/usr/bin/env python3
"""
Salesforce ID Tool

Features:
- Decode the base62 record number embedded in a 15/18-char Salesforce ID.
- Enumerate IDs from a starting integer value OR from the current ID's value.
- Output 15-char IDs by default; optional 18-char via Salesforce checksum algorithm.
- Multithreaded enumeration for speed (default 50 threads). With --threads 1,
  output order is strictly sequential.

Output rules:
- decode mode: prints ONLY the decoded integer.
- enum modes:
    - when --displayonly: print ONLY Salesforce IDs (15 or 18 chars), one per line.
    - otherwise: write ONLY Salesforce IDs to the file (one per line), NO console output.
"""

import argparse
import concurrent.futures
import datetime
import os
import sys
from textwrap import dedent
from typing import Iterable, List, Tuple
import threading
import queue

# ---- Base62 using Salesforce alphabet (0-9, A-Z, a-z) ----
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
BASE = len(ALPHABET)  # 62
MAX_BASE62_8 = BASE ** 8 - 1  # maximum value representable by 8 base62 chars


def int_to_base62(n: int, min_len: int = 1) -> str:
    """Convert non-negative int to Base62 string. Pads with '0' to min_len."""
    if n < 0:
        raise ValueError("Only non-negative integers are supported")
    if n == 0:
        s = "0"
    else:
        chars = []
        while n > 0:
            n, r = divmod(n, BASE)
            chars.append(ALPHABET[r])
        s = "".join(reversed(chars))
    if len(s) < min_len:
        s = "0" * (min_len - len(s)) + s
    return s


def base62_to_int(s: str) -> int:
    """Convert Base62 string (Salesforce alphabet) to int."""
    n = 0
    for ch in s:
        i = ALPHABET.find(ch)
        if i == -1:
            raise ValueError(f"Invalid Base62 character: {ch!r}")
        n = n * BASE + i
    return n


# ---- Salesforce 15->18 checksum algorithm (Python port of provided JS) ----
_MAPPING = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")


def id15_to_18(id15: str) -> str:
    """
    Convert a 15-char Salesforce ID to 18-char by computing the 3-char checksum suffix.
    Split into 3 segments of 5, reverse each segment, mark uppercase positions as '1',
    interpret as a 5-bit number (0..31), map to 'A'-'Z','0'-'5'.
    """
    if len(id15) != 15:
        raise ValueError("15->18 conversion requires exactly 15 characters")
    segments = [id15[i:i + 5] for i in range(0, 15, 5)]
    reversed_segments = [seg[::-1] for seg in segments]
    suffix_chars = []
    for seg in reversed_segments:
        bits = ''.join('1' if c.isupper() else '0' for c in seg)
        idx = int(bits, 2)
        suffix_chars.append(_MAPPING[idx])
    return id15 + ''.join(suffix_chars)


def normalize_to_15(sfid: str) -> str:
    """
    Accept 15 or 18 char Salesforce ID. If 18, strip suffix to yield 15 chars.
    Basic validation to ensure [A-Za-z0-9] and correct len.
    """
    if not sfid or not isinstance(sfid, str):
        raise ValueError("Salesforce ID must be a non-empty string")
    sfid = sfid.strip()
    if len(sfid) == 18:
        core = sfid[:15]
    elif len(sfid) == 15:
        core = sfid
    else:
        raise ValueError("Salesforce ID must be 15 or 18 characters long")
    if not core.isalnum():
        raise ValueError("Salesforce ID must be alphanumeric")
    return core


def split_id_components(id15: str) -> Tuple[str, str]:
    """
    Split a 15-char ID into:
      prefix7 = first 7 chars (object prefix 3 + instance id 3 + reserved 1)
      counter8 = last 8 chars (base62 record counter)
    """
    if len(id15) != 15:
        raise ValueError("Expected a 15-char ID")
    prefix7 = id15[:7]
    counter8 = id15[7:]
    return prefix7, counter8


def clamp_record_value(v: int) -> int:
    return max(0, min(MAX_BASE62_8, v))


def make_id(prefix7: str, value: int, to18: bool) -> Tuple[str, str, int]:
    """
    Compose a Salesforce ID from prefix7 and base62 value.
    Returns (id_out, counter_base62_8, value).
    """
    v = clamp_record_value(value)
    b62 = int_to_base62(v, min_len=8)  # always 8 chars
    id15 = prefix7 + b62
    if to18:
        id_out = id15_to_18(id15)
    else:
        id_out = id15
    return id_out, b62, v


def gen_value_sequence(start_value: int, seq: int) -> Iterable[int]:
    """
    Generate a sequence of integer values including start, moving up/down
    based on the sign of seq. |seq| is the count of IDs to produce.
    """
    if seq == 0:
        return []
    count = abs(seq)
    step = 1 if seq > 0 else -1
    current = start_value
    produced = 0
    while produced < count:
        if 0 <= current <= MAX_BASE62_8:
            yield current
        else:
            break
        current += step
        produced += 1


def default_output_filename(script_name: str) -> str:
    stem = os.path.splitext(os.path.basename(script_name))[0] or "sfid-tool"
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{stem}-{ts}.txt"


def write_results_ids(path: str, ids_only: List[str]) -> None:
    """Write only the Salesforce IDs, one per line (no header, no extras)."""
    with open(path, "w", encoding="utf-8") as f:
        for sfid_out in ids_only:
            f.write(f"{sfid_out}\n")


def normalize_mode(s: str) -> str:
    """Normalize mode value and support aliases d/efv/efc (case-insensitive)."""
    if not s:
        raise argparse.ArgumentTypeError("Mode is required.")
    m = s.strip().lower()
    aliases = {
        "decode": "decode",
        "d": "decode",
        "enum-from-value": "enum-from-value",
        "efv": "enum-from-value",
        "enum-from-current": "enum-from-current",
        "efc": "enum-from-current",
    }
    if m not in aliases:
        raise argparse.ArgumentTypeError(
            "Invalid --mode. Use one of: decode|d, enum-from-value|efv, enum-from-current|efc"
        )
    return aliases[m]


def main(argv=None) -> int:
    epilog = dedent("""
    EXAMPLES
      Decode the record counter (prints integer):
        sfid_tool.py -i 001Vc00000PHoN1IAL -m d

      Enumerate from an integer value upward (IDs saved to default file, no console output):
        sfid_tool.py -i 001Vc00000PHoN1IAL -m efv --start 366897425 --seq 10

      Enumerate downward 5 from the current ID value (print only, 18-char IDs):
        sfid_tool.py -i 001Vc00000PHoN1 -m efc --seq -5 --displayonly --to18

      Fixing the 3 last characters to make a valid 18-char ID:
        sfid_tool.py -i 001Vc00000PHoN1 -m efc --seq 1 --displayonly --to18

      Force sequential order (threads=1) and write to custom file:
        sfid_tool.py -i 001Vc00000PHoN1IAL -m efc --seq 100 --threads 1 --outfile out.txt

      Large parallel enumeration (order not guaranteed; file is written safely):
        sfid_tool.py -i 001Vc00000PHoN1IAL -m efv --start 0 --seq 500000 --threads 100

    NOTES
      - In enum modes, nothing is printed unless --displayonly is used.
      - decode mode prints ONLY the decoded integer.
      - When not using --displayonly, results are written to a text file (IDs only, one per line).
      - Valid base62 integer bounds for the 8-char counter: 0 .. 62^8 - 1.
    """).strip("\n")

    parser = argparse.ArgumentParser(
        description="Salesforce ID decode/enumeration tool (base62 record number)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=epilog,
    )
    # --id with -i short
    parser.add_argument(
        "-i", "--id",
        required=True,
        help="Salesforce ID (15 or 18 chars)",
    )

    # --mode with aliases
    parser.add_argument(
        "-m", "--mode",
        required=True,
        type=normalize_mode,
        help="Operation mode: decode|d, enum-from-value|efv, enum-from-current|efc",
    )

    # Enum parameters
    parser.add_argument(
        "--start",
        type=int,
        help="(optional) (enum-from-value) Starting integer value for 8-char base62 (0..62^8-1)",
    )
    parser.add_argument(
        "--seq",
        type=int,
        help="Number of IDs to generate. Positive=upward, Negative=downward (required for enum modes)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="(optional) Worker threads for enum modes (default 50). Use 1 for strict sequential output.",
    )
    parser.add_argument(
        "--displayonly",
        action="store_true",
        help="(optional) Do not write to file; only print results to stdout",
    )
    parser.add_argument(
        "--outfile",
        help="(optional) Output filename (for enum modes). Default is <scriptname>-<timestamp>.txt",
    )
    parser.add_argument(
        "--to18",
        action="store_true",
        help="(optional) Output 18-char IDs (default outputs 15-char)",
    )

    args = parser.parse_args(argv)

    # Normalize ID to 15 chars & split components
    try:
        id15 = normalize_to_15(args.id)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    try:
        prefix7, counter8 = split_id_components(id15)
        current_value = base62_to_int(counter8)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    # Mode: decode -> print integer only and exit
    if args.mode == "decode":
        print(current_value)
        return 0

    # Enum modes require --seq (non-zero)
    if args.seq is None or args.seq == 0:
        print("Error: --seq must be provided and non-zero for enumeration modes.", file=sys.stderr)
        return 2

    if args.mode == "enum-from-value":
        if args.start is None:
            print("Error: --start must be provided for --mode enum-from-value.", file=sys.stderr)
            return 2
        if args.start < 0 or args.start > MAX_BASE62_8:
            print(f"Error: --start must be between 0 and {MAX_BASE62_8}.", file=sys.stderr)
            return 2
        start_value = args.start
    else:
        # enum-from-current
        start_value = current_value

    # Build sequence of values
    values = list(gen_value_sequence(start_value, args.seq))
    if not values:
        # No stdout output since you want only IDs there; error goes to stderr
        print("No values generated (sequence may have exceeded bounds).", file=sys.stderr)
        return 3

    # ENUMERATION OUTPUT BEHAVIOR:
    # - displayonly: print IDs to stdout (only).
    # - else: write IDs to file (only), with thread-safe writer.
    if args.displayonly:
        # PRINT ONLY
        if args.threads <= 1:
            # Strict sequential
            for v in values:
                sfid_out, _, _ = make_id(prefix7, v, to18=args.to18)
                print(sfid_out)
        else:
            # Parallel; order not guaranteed
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as exe:
                futs = [exe.submit(make_id, prefix7, v, args.to18) for v in values]
                for fut in concurrent.futures.as_completed(futs):
                    sfid_out, _, _ = fut.result()
                    print(sfid_out)
    else:
        # FILE ONLY
        outfile = args.outfile or default_output_filename(sys.argv[0] if sys.argv else "sfid-tool.py")

        # Single writer thread consuming from a queue to avoid race conditions.
        q: "queue.Queue[str | None]" = queue.Queue(maxsize=10000)
        writer_error = {"exc": None}

        def writer():
            try:
                with open(outfile, "w", encoding="utf-8") as f:
                    while True:
                        line = q.get()
                        if line is None:
                            break
                        f.write(line)
            except Exception as e:
                writer_error["exc"] = e

        t = threading.Thread(target=writer, daemon=True)
        t.start()

        try:
            if args.threads <= 1:
                # Sequential generation, sequential writes
                for v in values:
                    sfid_out, _, _ = make_id(prefix7, v, to18=args.to18)
                    q.put(f"{sfid_out}\n")
            else:
                # Parallel generation; the single writer ensures no file races.
                with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as exe:
                    futs = [exe.submit(make_id, prefix7, v, args.to18) for v in values]
                    for fut in concurrent.futures.as_completed(futs):
                        sfid_out, _, _ = fut.result()
                        q.put(f"{sfid_out}\n")
        finally:
            # Signal writer to finish and wait for it
            q.put(None)
            t.join()

        if writer_error["exc"] is not None:
            print(f"Error writing to file '{outfile}': {writer_error['exc']}", file=sys.stderr)
            return 4

    return 0


if __name__ == "__main__":
    sys.exit(main())
