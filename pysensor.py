import sys
import argparse
import json
import jsongraph
from pprint import pprint

def parse_json(json_file):
    # TODO: parse JSON file, load into a data structure for analysis
    print("Not implemented yet!")
    with open(json_file) as f: #first, pull in json file
       graph = json.load(f)
    print(json.dumps(graph)) # dump graph, TODO: parse graph
    return graph

def parse_rom():
    # TODO: include R_PIPE API, call R2 and get the JSON from the ROM
    print("Not implemented yet!")

def main ():
    # set up the parser first
    # default parser args - filename, opens file for JSON parsing 
    # can also output JSON file as a .DOT file, or pull in a ROM and call R2 
    parser = argparse.ArgumentParser(description='Import and process M7700 JSON Graph files.')
    parser.add_argument('filename', metavar='filename', type=str, nargs=1,
                   help='JSON file for parsing')
    parser.add_argument('--dot', "-d",  metavar='dotfile', type=str, nargs=2, #flag and filename
                   help='--dot/-d dotfile: Convert to a graphviz dot flie')
    parser.add_argument('--rom', "-r", metavar='filename', type=bool,  #flag and filename
                   help='--rom/-r filename: Grab JSON for M7700 ROM')

    json_file = parser.parse_args('filename')
    dot_file = parser.parse_args('--dot,1')
    rom_file = parser.parse_args('--rom')
    
    # parse each file name, attempt to pull JSON from files
    if rom_file:
        parse_rom()

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
