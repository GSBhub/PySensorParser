#!/usr/bin/python
import sys
import argparse
import json
import jsongraph
import pprint
import r2pipe
import os
import logging
import re
from subprocess import check_call
from datetime import datetime

class callee:
    base_addr = 0x0 # address of the callee
    dest_addr = 0x0 # where the callee points
    json = ""      # json representation of function pointed to
    dot = ""       # dot representation of function pointed to
#    count = ""     # number of instructions in this callee

    def __init__(self, base_addr, dest_addr):
        self.base_addr = base_addr
        self.dest_addr = dest_addr

class caller:
    count = 0
    base_addr = 0x0 # addr of caller function
    callees = {}   # addr, callee pair dictionary 
    json = ""      # json representation of this caller function
    dot = ""       # dot represenation of this caller function

    def __init__(self, base_addr, base_cand):
        self.base_addr = base_addr
        self.callees[base_addr] = base_cand
        self.count += 1
        self.callees = {}
        self.json = ""
        self.dot = ""

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

def output_graphs(callers, r2):
        for func, func_caller in callers.items():
            logging.info ("Func: 0x{:04x} Caller: {}".format(func, func_caller))
            for addr, callee in func_caller.callees.items():
                logging.info ("Addr: 0x{:04x} Callee: {}".format(addr, callee))

        for func, func_caller in callers.items():
            try:
                func_str = '{:04x}'.format(func)
            except ValueError:
                func_str = '{}'.format(func)
    
            logging.info("Seeking to address 0x{} in radare.".format(func_str))
            logging.debug(r2.cmd("0x{:04x}".format(func)))   # seek to the address of this func
            logging.info("Creating main caller JSON, Disassembly")
            r2.cmd('aaa')
            func_caller.json = r2.cmd('agdj') # pull JSON disassembly from R2
            func_caller.dot = r2.cmd('agd')  # pull dot for function from R2
        
            new_path = '{}-{}'.format(func_str, func_caller.count)
            if not os.path.exists(new_path):
                os.makedirs(new_path)
            if not os.curdir == new_path:
                os.chdir(new_path)
            logging.debug("Path object for CALLER: {}".format(new_path))
            f1 = open ("{}.json".format(func_str), "w")
            f2 = open("{}.dot".format(func_str), "w")
            f1.write(func_caller.json)
            f2.write(func_caller.dot)
            f1.close()
            f2.close()

            for addr, callee in func_caller.callees.items():
                try: 
                    addr_str = str('0x{:04x}'.format(addr))
                except ValueError:
                    addr_str = str('{}'.format(addr))

                logging.debug(r2.cmd("s 0x{:04x}".format(callee.dest_addr)))    # seek to specified addr

                r2.cmd('aaa')
                callee.json = r2.cmd('agdj')
                callee.dot = r2.cmd('agd') 

                sub_path = '{}'.format(addr_str)
#               sub_path = re.sub("[^x0-9a-fA-F]+", "", sub_path) # remove any non-hex chars from string

                if not os.path.exists(sub_path):
                    os.makedirs(sub_path)  

                logging.info("Path object for CALLEE: {}".format(sub_path))
                os.chdir(sub_path)

                f3 = open ("{}.json".format(sub_path), "w")
                f4 = open("{}.dot".format(sub_path), "w")
                check_call(['dot','-Tpng', '-o', "{}.png".format(sub_path),"{}.dot".format(sub_path)])
                f3.write(callee.json)
                f4.write(callee.dot)
                f3.close()
                f4.close()
                os.chdir("..")
            os.chdir("..")
        cwd = os.getcwd()
        os.chdir(cwd)
        return callers    

# this method is responsible for
# - automatically parsing the rom file for caller candidates (that is, a function with 5 or more CALL type functions)
# - parsing the callees of those functions, that is, the functions called by the caller
# - creating a JSON graph structure of those functions
# - returning that graph to be parsed by other functions
def parse_rom(infile):

    print("Loading into R2...")
    r2 = r2pipe.open(infile)           # load infile into R2 - error if not found
    if r2:                             # assert the R2 file opened correctly
        r2.cmd('e asm.arch=m7700')     # set the architecture env variable
        logging.info("R2 loaded arch: " + r2.cmd('e asm.arch')) # check that arch loaded properly
        logging.info(r2.cmd('aa'))     # analyze all
        candidates = r2.cmd('/A call') # Use the /A call command in R2 to specify all R2 callees 
        logging.info("Result of R2 call search: {}".format(candidates))
        callers = get_callers(candidates) # grab all "callers" functions from the list of candidates
        output_graphs(callers, r2)    # output those callers and the callee functions to files
    else: 
        print("Error parsing R2")
    r2.quit()
    print("Quitting R2...")
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
            cand_list[int(candidate[0], 16)] = callee_candidate

    logging.info("Found {} potential candidates for grouping.".format(len(cand_list)))

    # form groupings based off of "close" call groupings
    func = current = None
    call = None
    callers = {}

    for address, candidate in sorted(cand_list.iteritems(), key=lambda (k,v): (v,k)): # iterate over items in-order (by address)

        logging.info("Candidate func address: {}\nCurrent address: {}".format(address, current))

        if (func == None):                # no defined caller, make a new one starting at first address
            func = current = address     # current starts at the base address, though functions may start earlier
            call = caller(address, candidate)

        elif (abs(address - current) <= 0xA): # a candidate is "close" to another if it is within 10 of the next address
            call.push(address, candidate)    # push a candidate into the caller
            current = address

        else:
            if (call.count > 5):                # if there are less than 5 candiates in the caller, discard
                callers[func] = call            # save the caller object, otherwise overwrite it    
            del call    
            func = current = None                   # clear current, start search for next candidate

    logging.info("Found {} groups of candidates.".format(len(callers)))

    return callers

def main ():
    # set up the parser first
    # default parser args - filename, opens file for JSON parsing 
    # can also output JSON file as a .DOT file, or pull in a ROM and call R2 
    parser = argparse.ArgumentParser(description='Import and process M7700 JSON Graph files.')

    parser.add_argument('filename', metavar='filename', nargs='+', type=str, default=sys.stdin, 
                   help='M7700 ROM file for parsing')

    logging.basicConfig(filename='log_filename.txt', level=logging.DEBUG)

    args = parser.parse_args()

    for infile in args.filename:
        if infile is not None:
            print("Opening file: {}".format(infile))
        #infile = value

        # do ROM-level analysis with R2pipe
        if (os.path.isfile(infile)):
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

            callers = parse_rom(infile)
            print ("Number of callers: {}".format(len(callers)))
        else: 
            print ("File '{}' not found".format(infile))

# start
main()