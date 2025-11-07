#!/usr/bin/env python3

import os, sys, argparse
from pathlib import Path

SEP = b'\xaa'         # observed separator between chunks
MAGIC = b'HLM1'        # observed message header
JOINER = ''            # how to join reversed tokens when producing reassembled text
STRIP_NONPRINT = True  # attempt to remove stray non-printable characters from token ends for readability

def is_printable_char(c):
    # keep common whitespace + printable ascii
    return 32 <= c < 127 or c in (9,10,13)

def clean_printable(s):
    # remove leading/trailing non-printable chars (but keep inner whitespace)
    # s is a str (already decoded with latin-1)
    # trim edges that are mostly nonprintable
    start = 0
    end = len(s)
    while start < end and not any(ord(ch) == ord(ch) and is_printable_char(ord(ch)) for ch in s[start:start+1]):
        start += 1
    while end > start and not any(is_printable_char(ord(ch)) for ch in s[end-1:end]):
        end -= 1
    return s[start:end]

def decode_messages(data):
    msgs = []
    idx = 0
    while True:
        pos = data.find(MAGIC, idx)
        if pos == -1:
            break
        # find next magic to bound this message
        next_pos = data.find(MAGIC, pos+len(MAGIC))
        if next_pos == -1:
            block = data[pos:]
            idx = len(data)
        else:
            block = data[pos:next_pos]
            idx = next_pos
        msgs.append(block)
    return msgs

def process_message(block):
    # block includes the leading 'HLM1' and any bytes after it
    # skip the MAGIC itself for token processing (but you can keep it if desired)
    payload = block[len(MAGIC):]
    # split on SEP
    tokens = payload.split(SEP)
    rev_tokens = []
    for t in tokens:
        if not t:
            rev_tokens.append('')  # preserve empties
            continue
        try:
            s = t.decode('latin-1', errors='replace')
        except Exception:
            s = ''.join(chr(b) for b in t)
        # reverse characters
        r = s[::-1]
        if STRIP_NONPRINT:
            r = clean_printable(r)
        rev_tokens.append(r)
    return rev_tokens

def make_pretty(text):
    # small heuristics to make the text more HL7-like / readable:
    # - replace repeated control sequences that look like encoding markers
    # - insert newlines on common HL7 segment IDs like MSH, PID, OBR, OBX, PV1, etc. (case-insensitive)
    segs = ['MSH','PID','NK1','PV1','OBR','OBX','AL1','GT1','DG1','Z']  # Z* are custom segments
    out = text
    # insert newline before known segment markers if they're immediate content
    for seg in segs:
        out = out.replace(seg, '\n'+seg)
        out = out.replace(seg.lower(), '\n'+seg.lower())
    # collapse multiple newlines
    out = '\n'.join([line.strip() for line in out.splitlines() if line.strip()!=''])
    return out

def main():
    p = argparse.ArgumentParser(description='Decode HLM1-style messages from a binary capture.')
    p.add_argument('infile', help='input binary file (e.g. udp_combined.bin)')
    p.add_argument('outdir', help='output directory to write results')
    args = p.parse_args()

    infile = Path(args.infile)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    data = infile.read_bytes()
    msgs = decode_messages(data)
    if not msgs:
        print('No messages starting with', MAGIC, 'found in', infile)
        return

    # write per-message reversed tokens and reassembled variants
    rev_tokens_path = outdir / 'messages_reversed_tokens.txt'
    reassembled_path = outdir / 'messages_reassembled.txt'
    pretty_path = outdir / 'messages_pretty.txt'

    with rev_tokens_path.open('w', encoding='utf-8', errors='replace') as f_tok, \
         reassembled_path.open('w', encoding='utf-8', errors='replace') as f_re, \
         pretty_path.open('w', encoding='utf-8', errors='replace') as f_pre:
        for i,blk in enumerate(msgs):
            rev = process_message(blk)
            # write tokens (one per line) with header info
            f_tok.write(f'-- MESSAGE {i} --\n')
            for j,t in enumerate(rev):
                f_tok.write(f'[{j:03d}] {t}\n')
            f_tok.write('\n\n')

            # reassemble by concatenating reversed tokens (JOINER controls spacing)
            assembled = JOINER.join(rev).strip()
            f_re.write(f'-- MESSAGE {i} --\n')
            f_re.write(assembled + '\n\n')

            # make a 'pretty' attempt for quick inspection
            pretty = make_pretty(assembled)
            f_pre.write(f'-- MESSAGE {i} --\n')
            f_pre.write(pretty + '\n\n')

    print('Wrote:')
    print(' -', rev_tokens_path)
    print(' -', reassembled_path)
    print(' -', pretty_path)
    print('\nOpen the *_pretty.txt in your editor to inspect, or the *_tokens.txt to see token-by-token reversals.')
    print('If you want different behavior (keep 0xaa markers, use a different separator, or insert length prefixes), edit SEP / JOINER variables at the top of the script.')

if __name__ == "__main__":
    main()
