# Auraditor Tools

This directory contains standalone command-line utilities for Salesforce security testing that can be used independently of the Burp Suite extension.

## sfidenum.py

Python tool for decoding and enumerating Salesforce IDs.

### Requirements

- Python 3.6+
- No external dependencies (uses only standard library)

### Features

- **Decode** the base62 record number from a 15/18-character Salesforce ID
- **Enumerate** IDs from a starting value or from current ID's value
- **Generate** 15 or 18-character IDs with valid checksums
- **Multithreaded** enumeration for speed (default 50 threads)

### Usage

#### 1. Decode Record Number

Extract the decimal record number from a Salesforce ID:

```bash
python3 sfidenum.py -i 001Vc00000PHoN1IAL -m decode
# Output: 366897425
```

#### 2. Fix Invalid 18-char ID

Generate valid checksum for a 15-char ID:

```bash
python3 sfidenum.py -i 001Vc00000PHoN1 -m efc --seq 1 --displayonly --to18
# Output: 001Vc00000PHoN1IAL
```

#### 3. Enumerate IDs from Current Value

Generate IDs starting from the current ID's record number:

```bash
# 10 IDs upward (will save to file)
python3 sfidenum.py -i 001Vc00000PHoN1IAL -m efc --seq 10

# 5 IDs downward (display only, no file)
python3 sfidenum.py -i 001Vc00000PHoN1 -m efc --seq -5 --displayonly --to18
```

#### 4. Enumerate from Specific Value

Generate IDs starting from a specific decimal record number:

```bash
# Start from record 0, generate 1000 IDs
python3 sfidenum.py -i 001Vc00000PHoN1IAL -m efv --start 0 --seq 1000

# Custom output file with 18-char IDs
python3 sfidenum.py -i 001Vc00000PHoN1 -m efv --start 100 --seq 50 --to18 --outfile my-ids.txt
```

#### 5. Sequential vs Parallel Output

```bash
# Sequential order (threads=1) - order guaranteed
python3 sfidenum.py -i 001Vc00000PHoN1IAL -m efc --seq 100 --threads 1 --outfile out.txt

# Parallel generation (default 50 threads) - faster but unordered
python3 sfidenum.py -i 001Vc00000PHoN1IAL -m efv --start 0 --seq 500000 --threads 100
```

### Command-Line Options

```
Required Arguments:
  -i, --id ID           Salesforce ID (15 or 18 characters)
  -m, --mode MODE       Operation mode: decode|d, enum-from-value|efv, enum-from-current|efc

Enumeration Arguments:
  --start INT           (enum-from-value only) Starting record number (0 to 62^8-1)
  --seq INT             Number of IDs to generate (positive=up, negative=down)
  --threads INT         Worker threads for enumeration (default: 50, use 1 for sequential)
  --displayonly         Print results to stdout instead of file
  --outfile FILE        Custom output filename (default: sfidenum-<timestamp>.txt)
  --to18                Generate 18-character IDs with checksum (default: 15-char)
```

### Mode Aliases

- `decode` or `d` - Decode mode
- `enum-from-value` or `efv` - Enumerate from specific value
- `enum-from-current` or `efc` - Enumerate from current ID's value

### Output Behavior

**Decode Mode:**
- Prints ONLY the decoded integer to stdout
- No file output

**Enumeration Modes:**
- With `--displayonly`: Prints IDs to stdout (one per line), no file created
- Without `--displayonly`: Writes IDs to file (one per line), no console output
- Default filename: `sfidenum-YYYYMMDD-HHMMSS.txt`

### Examples

#### Example 1: Decode and Understand an ID

```bash
# First, decode the record number
python3 sfidenum.py -i 001Vc00000PHoN1IAL -m d
# Output: 366897425

# Then enumerate around that value
python3 sfidenum.py -i 001Vc00000PHoN1 -m efc --seq 5 --displayonly --to18
```

#### Example 2: Generate IDs for Testing

```bash
# Generate 1000 Account IDs starting from 0
python3 sfidenum.py -i 001Vc00000PHoN1IAL -m efv --start 0 --seq 1000 --to18
# Output: File created with 1000 IDs
```

#### Example 3: Find Valid Checksum

```bash
# If you have 001Vc00000PHoN1XXX (invalid checksum)
python3 sfidenum.py -i 001Vc00000PHoN1XXX -m efc --seq 1 --displayonly --to18
# Output: 001Vc00000PHoN1IAL (correct checksum)
```

### Salesforce ID Structure

A Salesforce ID consists of:

**15-Character Format:**
- Characters 0-2: Object prefix (identifies object type)
- Characters 3-5: Instance ID (Salesforce org instance)
- Character 6: Reserved
- Characters 7-14: Record number (8-char base62)

**18-Character Format:**
- First 15 characters as above
- Last 3 characters: Checksum (for case-insensitive uniqueness)

### Base62 Encoding

Salesforce uses base62 encoding with alphabet: `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`

Maximum record number: 62^8 - 1 = 218,340,105,584,895

### Common Object Prefixes

- `001` - Account
- `003` - Contact
- `005` - User
- `006` - Opportunity
- `00Q` - Lead
- `500` - Case
- `701` - Campaign

Full list: https://help.salesforce.com/s/articleView?id=000385203&type=1

### Performance Notes

- Default 50 threads provides good balance of speed and resource usage
- For large enumerations (>100k IDs), consider using more threads
- Thread count of 1 guarantees sequential output order
- File writing is thread-safe regardless of thread count

### Security Considerations

⚠️ **Use only for authorized testing**

This tool is intended for security testing of Salesforce applications you are authorized to test. Unauthorized enumeration of Salesforce IDs may violate terms of service and applicable laws.

### References

- Salesforce IDs Explained: https://codebycody.com/salesforce-ids-explained/
- Object Key Prefixes: https://help.salesforce.com/s/articleView?id=000385203&type=1
