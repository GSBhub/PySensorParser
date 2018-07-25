import sys
import argparse
import json
import jsongraph
from pprint import pprint

def main ():
    parser = argparse.ArgumentParser(description='Import and process M7700 JSON Graph files.')
    parser.add_argument('filename', metavar='filename', type=str, nargs='+',
                   help='JSON file for parsing')
    parser.add_argument('--dot', dest='out.dot',
                   help='--dot: Convert to a graphviz dot flie')

    args = parser.parse_args()
    
    # parse each file name, attempt to pull JSON from files
    for fn in args.filename: 
        with open(fn) as f: 
            graph = json.load(f)

        print(json.dumps(graph)) # dump graph, todo: parse graph

main()
