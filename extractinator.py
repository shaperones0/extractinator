VERSION = "0.0.1"


from dataclasses import dataclass
from typing import List, Optional, Iterator
from enum import Enum


@dataclass
class Signature:
    name: str
    start: bytes
    end: bytes


class OccurrenceType(Enum):
    START = 1
    END = 2


@dataclass
class Occurrence:
    type: OccurrenceType
    name: str
    pos_start: int
    pos_end: int


SIGNATURES = {
    'png': Signature("png", b"\x89PNG\x0d\x0a\x1a\x0a", b"IEND\xae\x42\x60\x82")
}


def substr_check(input, pos_start, pos_end, thing):
    for i in range(pos_start, pos_end):
        if input[i] != thing[i - pos_start]:
            return False
    return True


def match_signature(content_bytes: List, i: int, signatures: List[Signature], is_start=True) -> Optional[Signature]:
    for signature_inst in signatures:
        signature = signature_inst.start if is_start else signature_inst.end
        signature_len = len(signature)

        if len(content_bytes) > i + signature_len and substr_check(content_bytes, i, i + signature_len, signature):
            return signature_inst


def sniff(content_bytes: bytes, signatures: List[Signature]) -> Iterator[Occurrence]:
    substr_start = None
    substr_signature = None

    for i in range(len(content_bytes)):
        # if i % 10000 == 0:
        #     print(i)
        if substr_start is None:
            # We have not encountered starting signature of the substring, look for start signature
            matching_signature = match_signature(content_bytes, i, signatures, True)
            if matching_signature is not None:
                substr_start = i
                substr_signature = matching_signature
                yield Occurrence(OccurrenceType.START, matching_signature.name, i, -1)
        else:
            # We have encounted starting signature of the substring, look for end signature
            matching_signature = match_signature(content_bytes, i, [substr_signature], False)
            if matching_signature is not None:
                yield Occurrence(OccurrenceType.END, matching_signature.name, substr_start, i + len(matching_signature.end) + 1)
                substr_start = None
                substr_signature = None
       

if __name__ == "__main__":
    import sys, os

    greetings_str = f"========================== EXTRACTINATOR {VERSION} =========================="
    terminal_width = len(greetings_str)
    print(greetings_str)

    # Parse them args
    if len(sys.argv) == 1:
        print(f"""This is command line utility.
Usage:
\textractinator.py <input file> <format1> [<format2> ...]
Supported formats: png
{' <<< Press any key to exit >>> ':=^{terminal_width}}""")
        os.system("pause")
        exit(0)

    elif len(sys.argv) == 2:
        target_fname = sys.argv[1]
        print("""Please type the desired formats, separated by whitespace.
Supported formats: png""")
        formats = input("> ").split()
    else:
        target_fname = sys.argv[1]
        formats = sys.argv[2:]
    
    # Get signatures
    signatures = [SIGNATURES[fmt] for fmt in formats]

    print(f"""INPUT:
File: {target_fname}
Formats: {' '.join(formats)}
{' PROCESSING DETAILS ':=^{terminal_width}}""")
    
    with open(target_fname, 'rb') as fin:
        input_bytes = fin.read()
    
    occurrence_count = 0
    for occurrence in sniff(input_bytes, signatures):
        if occurrence.type == OccurrenceType.START:
            print(f"Found {occurrence.name} at {hex(occurrence.pos_start)} ..", end="")
            occurrence_count += 1
        else:
            print(f". {hex(occurrence.pos_end)}", end="")
            occurrence_bytes = input_bytes[occurrence.pos_start : occurrence.pos_end]
            output_fname = f"{occurrence_count}.{occurrence.name}"
            with open(output_fname, 'wb') as fout:
                fout.write(occurrence_bytes)
            print(f" - saved as {output_fname}")
    print(f"Finished processing {target_fname} with {occurrence_count} files found inside!")
