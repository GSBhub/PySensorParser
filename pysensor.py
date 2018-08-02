import sys
import argparse
import json
import jsongraph
import pprint
import r2pipe

# parse func information from JSON file
# either compare to a function and return information about the tree, or
def parse_json(json_tree, comp):
    # TODO: parse JSON file, load into a data structure for analysis
    graph = json.load(json_tree) # create JSON object from loaded graph

    if comp:
        # comp method compares the added JSON function to the graph, for similarity
        print("WIP")
    else: 
        # otherwise, traverse the graph and dump the children
        print(json.dumps(graph)) # dump graph, TODO: parse graph

    return graph

# this method is responsible for
# - automatically parsing the rom file for caller candidates (that is, a function with 5 or more CALL type functions)
# - parsing the callees of those functions, that is, the functions called by the caller
# - creating a JSON graph structure of those functions
# - returning that graph to be parsed by other functions
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

    parser.add_argument('filename', metavar='filename', nargs='?', type=argparse.FileType('r'), default=sys.stdin, 
                   help='M770 ROM file for parsing')

    parser.add_argument('-j','--json', action="store_true", #flag and filename
                   help='Compare JSON method with another JSON tree, find similarities')

  #  parser.add_argument('-d','--dot', metavar='dotfile', type=argparse.FileType('w'), default=sys.stdout,  #flag and filename
  #                 help='Convert to a graphviz dot flie')

  #  args = parser.parse_args(['-dr'])
    args = parser.parse_args()
    infile = args.filename
    #dot_file = args.dot
    json_compare = args.rom

    # parse each file name, attempt to pull JSON from files
    if json_compare:
        ret = parse_json(infile, None)
    else:
        ret = parse_json(parse_rom(infile), None)

    print(ret)    
#    if dot_file:
#        #TODO: convert JSON to DOT, output
#        dot_file.write((json.dumps(ret))) # dump graph, TODO: parse graph
#        dot_file.close()

# call main, start everything up
main()