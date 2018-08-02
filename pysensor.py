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

    # first, call R2 and find candidates from the ROM
    get_rom_candidates(infile)


    return ret

def get_rom_candidates(infile):
    print("Loading into R2...")

    # load infile into R2
    r2 = r2pipe.open(infile)

    if r2: # assert the R2 file opened correctly
        r2.cmd('aa') # analyze all
        candidates = r2.cmd('/a call') # Use the /a call command in R2 to specify all R2 callees 
        candidates = check_candidates(candidates)

    # TODO: the rest of this
    # Grab the function name of each of those calls

    # Create the Caller dictionary with each main function of callees, made up of caller objects

    # Each caller object has the addresses of what they call

    # For each caller, the address is paired with the JSON of the corresponding function

    # After the JSON is fully parsed, the data structure is returned to the PARSE_ROM func

    else: 
        print("Error parsing R2")

    print("Not implemented yet!")
    return 0

# Purge all addresses that aren't within 5 lines of at least 1 other call, and number less than 5 total
def check_candidates(candidates):
    for candidate in candidates:
        print ("Candidate: " + candidate)
    return 0

def main ():
    # set up the parser first
    # default parser args - filename, opens file for JSON parsing 
    # can also output JSON file as a .DOT file, or pull in a ROM and call R2 
    parser = argparse.ArgumentParser(description='Import and process M7700 JSON Graph files.')

    parser.add_argument('filename', metavar='filename', nargs='?', type=argparse.FileType('r'), default=sys.stdin, 
                   help='M7700 ROM file for parsing')

    parser.add_argument('-j','--json', action="store_true", #flag and filename
                   help='Compare JSON method with another JSON tree, find similarities')

  #  parser.add_argument('-d','--dot', metavar='dotfile', type=argparse.FileType('w'), default=sys.stdout,  #flag and filename
  #                 help='Convert to a graphviz dot flie')

  #  args = parser.parse_args(['-dr'])
    args = parser.parse_args()
    infile = args.filename
    #dot_file = args.dot
    json_compare = args.json

    # parse each file name, attempt to pull JSON from files
    if json_compare: # JSON file and comparison provided
        ret = parse_json(infile, args.json)
    else:            # do ROM-level analysis with R2pipe
        ret = parse_json(parse_rom(infile), None)

    print(ret)    
#    if dot_file:
#        #TODO: convert JSON to DOT, output
#        dot_file.write((json.dumps(ret))) # dump graph, TODO: parse graph
#        dot_file.close()

# call main, start everything up
main()