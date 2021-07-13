import argparse
import os
import json


def read_all_traces(trace_folder):
    traces = []
    for root, _, files in os.walk(trace_folder):
        for f in files:
            fpath = os.path.join(root, f)
            with open(fpath, "rb") as trace_file:
                data = trace_file.readlines()
                traces.append(data)
        break  # Hanele only high-level directory
    return traces


def extract_addresses_from_trace(traces):
    addresses = []
    for trace in traces:
        for addr in trace:
            cur_json = json.loads(addr)
            if cur_json.get('edge', None):
                addr_a, addr_b = cur_json['edge']
                addresses.append(addr_a)
                addresses.append(addr_b)
            elif cur_json.get('trace_enable'):
                addresses.append(cur_json['trace_enable'])
    return addresses


def export_addresses_to_file(addresses, out_file):
    with open(out_file, "wb") as f:
        f.write(bytes('\n'.join(addresses), 'ascii'))


def get_args():
    parser = argparse.ArgumentParser(description='Convert PT trace files from kAFL to a Lighthouse-compatible format')
    parser.add_argument('traces_folder', help='Path to PT traces folder')
    parser.add_argument('output_path', help='Path to output results')
    return parser.parse_args()


def main():
    args = get_args()
    traces_folder, output_path = args.traces_folder, args.output_path
    traces = read_all_traces(traces_folder)
    addresses = list(extract_addresses_from_trace(traces))
    addresses = [hex(addr) for addr in addresses]
    export_addresses_to_file(addresses, output_path)


if __name__ == '__main__':
    main()
