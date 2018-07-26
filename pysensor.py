import sys
import argparse
import json
import jsongraph
from pprint import pprint

# parse func information from JSON file
def parse_json(json_file):
    # TODO: parse JSON file, load into a data structure for analysis
    with open(json_file) as f: #first, pull in json file
       graph = json.load(f)
    print(json.dumps(graph)) # dump graph, TODO: parse graph
    return graph

# parse json information from ROM
def parse_rom(infile):
    # TODO: include R_PIPE API, call R2 and get the JSON from the ROM
    print("Not implemented yet!")
    ret = infile
    return ret

def main ():
    # set up the parser first
    # default parser args - filename, opens file for JSON parsing 
    # can also output JSON file as a .DOT file, or pull in a ROM and call R2 
    parser = argparse.ArgumentParser(description='Import and process M7700 JSON Graph files.')

    parser.add_argument('filename',metavar='filename', nargs='?', type=argparse.FileType('r'), default=sys.stdin, 
                   help='JSON file for parsing')

    parser.add_argument('-d','--dot', metavar='dotfile', type=argparse.FileType('w'), default=sys.stdout,  #flag and filename
                   help='Convert to a graphviz dot flie')
    parser.add_argument('-r','--rom', metavar='filename', type=bool,  #flag and filename
                   help='Grab JSON for M7700 ROM')

    json_file = parser.parse_args()
    dot_file = parser.parse_args()
    rom_file = parser.parse_args()
    
    # parse each file name, attempt to pull JSON from files
    if rom_file:
        ret = parse_json(parse_rom(json_file))
    else:
        ret = parse_json(json_file)
        
    if dot_file:
        outfile = parser.parse_args('--dot,2')
        #TODO: convert JSON to DOT, output
        # convert RET
        with open(outfile, "w") as f: #make a new .dot outfile
            f.write(json.dumps(ret)) # dump graph, TODO: parse graph
            f.close()

# call main, start everything up
main()
