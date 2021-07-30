import os
import sys
import re

DELIMITER = b'======================================'

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} [CRASH_FILE] [OUTPUT_CRASH_FILE]")
        sys.exit(1)

    crash_log_path = sys.argv[1]
    with open(crash_log_path, 'rb') as f:
        crashes = f.read()

    crash_list = crashes.split(DELIMITER)
    extracted_crash_list = []

    for crash in crash_list:
        extracted_crash_list.append(re.findall(b'.*\) (.*)', crash))

    extracted_crash_list = list(set(tuple(i) for i in extracted_crash_list))
    total_crashes = len(extracted_crash_list)

    with open(sys.argv[2], 'wb') as f:
        f.write(b'Total Crashes: %d\n\n' % total_crashes)
        for crash in extracted_crash_list:
            if not crash:
                continue
            f.write(b'\n'.join(crash))
            f.write(b'\n============================\n\n')
    print(extracted_crash_list)

if __name__ == '__main__':
    main()