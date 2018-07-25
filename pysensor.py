import sys
import json
from pprint import pprint


def main ():
    fn = sys.argv[1] # really lazy arg parser for now, should add more options

    with open(fn) as f: # pull JSON from file
        graph = json.load(f)

    print(json.dumps(graph)) # dump graph, todo: parse graph

main()