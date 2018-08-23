import sys
import argparse
import json
import jsongraph
import pprint
import r2pipe
from datetime import datetime
import os
import logging
import re

class callee:
    base_addr = 0x0 # address of the callee
    dest_addr = 0x0 # where the callee points
    json = ""      # json representation of function pointed to
    dot = ""       # dot representation of function pointed to
#    count = ""     # number of instructions in this callee

    def __init__(self, base_addr, dest_addr):
        self.base_addr = base_addr
        self.dest_addr = dest_addr

    def set_json(self, json):
        self.json = json

    def set_dot(self, dot):
        self.dot = dot

class caller:
    count = 0
    base_addr = 0x0 # addr of caller function
    callees = {}   # addr, callee pair dictionary 
    json = ""      # json representation of this caller function
    dot = ""       # dot represenation of this caller function

    def __init__(self, base_addr):
        self.base_addr = base_addr

    def push(self, base_addr, callee):
        self.count += 1
        self.callees[base_addr] = callee

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
    print("Loading into R2...")

    # load infile into R2
    r2 = r2pipe.open(infile)

    if r2:                             # assert the R2 file opened correctly
        r2.cmd('e asm.arch=m7700')     # set the architecture env variable
        logging.info("R2 loaded arch: " + r2.cmd('e asm.arch'))
        logging.info(r2.cmd('aa'))                # analyze all
        candidates = r2.cmd('/A call') # Use the /A call command in R2 to specify all R2 callees 
        
        logging.info(candidates)

        callers = get_callers(candidates)
        cwd = os.getcwd()

        logging.info(cwd)

        for func, func_caller in callers.items():
            try:
                func_str = '{:04x}'.format(func)
            except ValueError:
                func_str = '{}'.format(func)
    
            logging.info("Seeking to address 0x{} in radare.".format(func_str))
            logging.debug(r2.cmd("s {:04x}".format(func)))   # seek to the address of this func
            logging.info("Creating main caller JSON, Disassembly")
            r2.cmd('aaa')
            func_caller.json = r2.cmd('agdj') # pull JSON disassembly from R2
            func_caller.dot = r2.cmd('agd')  # pull dot for function from R2
        
            new_path = '{}-{}'.format(func_str, func_caller.count)
#            if not os.path.exists(new_path):
#                os.makedirs(new_path)
#            if not os.curdir == new_path:
#                os.chdir(new_path)
            logging.debug("Path object for CALLER: {}".format(new_path))
#            f1 = open ("{}.json".format(func_str), "w")
#            f2 = open("{}.dot".format(func_str), "w")
#            f1.write(func_caller.json)
#            f2.write(func_caller.dot)
#            f1.close()
#            f2.close()

            #TODO: I'm an idiot, this is seeking to the JSR call and not the target that the JSR Points to
            for addr, callee in func_caller.callees.items():
                try: 
                    addr_str = '0x{:04x}'.format(addr)
                except ValueError:
                    addr_str = '{}'.format(addr)
                logging.debug(r2.cmd("s {}".format(addr_str)))        # now do the same for everything else within the caller struct
                #logging.info("Creating main function JSON, Disassembly")

                r2.cmd('aaa')
                callee.json = r2.cmd('agdj')
                callee.dot = r2.cmd('agd') 

                sub_path = '{}'.format(addr_str)
#                if not os.path.exists(sub_path):
#                    os.makedirs(sub_path)              
                logging.info("Path object for CALLEE: {}".format(sub_path))
                logging.info("Callee JSON: {}".format(callee.json))
#                os.chdir(sub_path)
#                f3 = open ("{}.json".format(addr_str), "w")
#                f4 = open("{}.dot".format(addr_str), "w")
#                f3.write(callee.json)
#                f4.write(callee.dot)
#                f3.close()
#                f4.close()
#                os.chdir("..")
#            os.chdir("..")
#        os.chdir(cwd)
    # For each caller, the address is paired with the JSON of the corresponding function
    # After the JSON is fully parsed, the data structure is returned to the PARSE_ROM func
        r2.quit()
    
    else: 
        print("Error parsing R2")
        r2.quit()

    return callers

# helper function to check if a string is a hex string or not
def isHex(num): 
    try:
        int (num, 16)
        return True
    except ValueError:
        return False

# Purge all addresses that aren't within 5 lines of at least 1 other call, and number less than 5 total
def get_callers(candidates):

    cand_str = candidates.splitlines()
    cand_list = {} # dictionary of address, and the candidate object

    # place all candidates into the above dictionary
    for candidate in cand_str:
        logging.debug("Candidate: {}".format(candidate))
        candidate = candidate.split()
        if isHex(candidate[3]): # Don't add any non-hex function calls, for the broken instructions
            callee_candidate = callee(int(candidate[0], 16), int(candidate[3], 16))
            cand_list[callee_candidate.base_addr] = callee_candidate

    logging.info("Found {} potential candidates for grouping.".format(len(cand_list)))

    # form groupings based off of "close" call groupings
    func = current = None
    call = None
    callers = {}

    for address, candidate in sorted(cand_list.iteritems(), key=lambda (k,v): (v,k)): # iterate over items in-order (by address)

        logging.debug("Candidate func address: {}\nCurrent address: {}".format(address, current))

        if (func == None):                # no defined caller, make a new one starting at first address
            func = current = address     # current starts at the base address, though functions may start earlier
            call = caller(address)

        elif (abs(address - current) <= 0xA): # a candidate is "close" to another if it is within 10 of the next address
            call.push(address, candidate)    # push a candidate into the caller
            current = address

        else:
            if (call.count > 3):             # if there are less than 5 candiates in the caller, discard
                callers[func] = call      # save the caller object, otherwise overwrite it
            func = current = None                   # clear current, start search for next candidate

    logging.info("Found {} groups of candidates.".format(len(callers)))

    return callers

def main ():
    # set up the parser first
    # default parser args - filename, opens file for JSON parsing 
    # can also output JSON file as a .DOT file, or pull in a ROM and call R2 
    parser = argparse.ArgumentParser(description='Import and process M7700 JSON Graph files.')

    parser.add_argument('filename', metavar='filename', nargs='?', type=str, default=sys.stdin, 
                   help='M7700 ROM file for parsing')

    parser.add_argument('-j','--json', action="store_true", #flag and filename
                   help='Compare JSON method with another JSON tree, find similarities')

    logging.basicConfig(filename='log_filename.txt', level=logging.DEBUG)



  #  parser.add_argument('-d','--dot', metavar='dotfile', type=argparse.FileType('w'), default=sys.stdout,  #flag and filename
  #                 help='Convert to a graphviz dot flie')

  #  args = parser.parse_args(['-dr'])
    args = parser.parse_args()
    infile = args.filename
    #dot_file = args.dot
    json_compare = args.json

    # parse each file name, attempt to pull JSON from files
    if json_compare: # JSON file and comparison provided
        ret = open(infile, 'r')

        ret = parse_json(infile, args.json)

    else:            # do ROM-level analysis with R2pipe
        #ret = parse_json(parse_rom(infile), None)

        regex = re.search(r'[A-Z]{2}\d\d', infile) # pull the ECU model from the filename
        dir_title =  regex.group(0)
        working_dir = '{}'.format(dir_title)

        if not os.path.exists(working_dir):
            os.makedirs(working_dir)
        if not os.curdir == working_dir:
            os.chdir(working_dir)
        
        regex = re.search(r'\d\w+-\d\w+-\w{1,4}', infile) # get the ROM from the filename
        dir_title =  regex.group(0)
        working_dir = '{}'.format(dir_title)

        if not os.path.exists(working_dir):
            os.makedirs(working_dir)
        if not os.curdir == working_dir:
            os.chdir(working_dir)

        ret = parse_rom(infile)

#    print(ret)    
#    if dot_file:
#        #TODO: convert JSON to DOT, output
#        dot_file.write((json.dumps(ret))) # dump graph, TODO: parse graph
#        dot_file.close()

# start
main()