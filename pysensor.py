#!/usr/bin/python
"""
    This branch of the pysensor module takes a list of found addresses for likely sensors
    and returns a list of the sensor values for each of those addresses. Still very much a WIP
"""
import sys
import argparse
import json
import jsongraph
import pprint
import r2pipe
import os
import logging
import re
import subprocess
import networkx as nx
import pygraphviz
import md5
import pprint
import collections
import itertools
from collections import OrderedDict
from networkx.drawing import nx_agraph
from subprocess import check_call
from datetime import datetime

# template for all function data types

visited = {}
last_visited = {}
functions = []
feature_visited = list()

# Predefined functions containing sensor addresses for comparisions from the USDM 93 EG33
sensors = {
    'batt_voltage': ['0x9a56', '0x9f5b', '0xa166', '0xa307', '0xae2c', '0xd982', '0xe1cd'],
    'vehicle_speed': ['0x9be8', '0x9dce', '0xa59d', '0xa9a7', '0xafc6', '0xb5fc', '0xb960'],
    'engine_speed': ['0xa59d', '0xa5ec', '0xa9a7', '0xafc6', '0xb5bf', '0xb960', '0xc356'],
    'water_temp': ['0x9b46', '0xab56'],
    'ignition_timing': ['0xdb1a', '0xda0f'],
    'airflow': ['0xddcd'],
    'throttle_position': ['0xe1cd'],
    'knock_correction': ['0xafc6']
}

sensor_values = {
    'batt_voltage': '0x102f',
    'vehicle_speed': '0x1071',
    'engine_speed': '0x106f',
    'water_temp': '0x1185',
    'ignition_timing': '0x10a2',
    'airflow': '0x1283',
    'throttle_position': '0x128c',
    'knock_correction': '0x12a7'

}

class instruction:

    def __init__(self, base_addr, opcode):
        self.base_addr = hex(base_addr)
        params = opcode.split()
        self.opcode = params[0]
        self.params = params[1:]

    def __str__(self):
        if self.params:
            ret = "OP: {}\nParams: {}\n".format(self.opcode, self.params)
        else:
            ret = "OP: {}\n".format(self.opcode)
        return ret

class block:
    base_addr = 0x0
    fail = None
    jump = None

    def __init__(self, base_addr, seq_json):
        self.base_addr = hex(base_addr)
        self.seq_inst = OrderedDict()

        for op in seq_json:

            self.seq_inst[op[u'offset']] = instruction(op[u'offset'], op[u'opcode'])

    # returns a hash of the instructions
    def get_seq_inst(self): 
        temp = ur""
        for instruction in self.seq_inst.values():
            temp = temp + ur"{}".format(instruction.opcode)
        #logging.debug("block addr: {}, temp: {}\n".format(self.base_addr, temp))
        return [(md5.new(temp).hexdigest())]
    
    def ret_instruct_list(self):
        temp = ur""
        for instruction in self.seq_inst.values():
            temp = temp + ur"{}".format(instruction.opcode)
        #logging.debug("block addr: {}, temp: {}\n".format(self.base_addr, temp))
        return [temp]

    def print_inst(self):
        for instruction in self.seq_inst.itervalues():
            print(instruction)

    def __str__(self):
        ret = "Base_addr: 0x{:04x}\n".format(self.base_addr)
        if self.fail:
            ret += "\tFail: 0x{:04x}\n".format(self.fail.base_addr)
        if self.jump:
            ret += "\tJump: 0x{:04x}\n".format(self.jump.base_addr)
        return ret

    def gen_features(self, start):
        features = {0:"", 1:""}
        li = self.seq_inst
        found = False
        for instr in li.items():
            if start == instr: 
                found = True
                features[0] = "{}{}".format(features[0], instr[1].opcode)
            elif found:
                features[0] = "{}{}".format(features[0], instr[1].opcode)
            else:
                features[1] = "{}{}".format(features[1], instr[1].opcode)
        
        features.update(self.feature_gen_p2())

        return features

    def feature_gen_p2(self):
        features = {}
        n = 2
        li = self.seq_inst
        keys = li.keys()
        vals = li.values()
        
        for val in vals:
            feat = ""
            start = vals.index(val)
            sub_list = vals[start: start + n - 1]
            for instr in sub_list:
                feat = "{}{}".format(feat, instr.opcode)
        
            # append first instr of next blocks
            if self.fail is not None:
                feat = "{}{}".format(feat, self.fail.seq_inst.get(int(self.fail.base_addr, 16)).opcode)
            if self.jump is not None:
                feat = "{}{}".format(feat, self.jump.seq_inst.get(int(self.jump.base_addr, 16)).opcode)
            
            features[val.base_addr] = feat

        return features

class CFG:
    first = None 

    def __init__(self, json):
        if json:
            self.json = json[0]
        else:
            self.json = ""
        if u'offset' in self.json:
            self.base_addr = hex(json[0][u'offset'])
            if u'blocks' in json[0]:
                blocks = json[0][u'blocks']
                dict_block = {}
                # pass addr of first block, ops of first block, and pointers of first block

                self.first = block(blocks[000][u'offset'], blocks[000][u'ops'])

                # create a dictionary of all blocks
                for blk in blocks:
                    dict_block [blk[u'offset']] = [block(
                    blk[u'offset'], 
                    blk[u'ops']), blk]

                # match up all the block objects to their corresponding jump, fail addresses
                for key, pair in dict_block.items():
                    block_obj = pair[0]
                    block_json = pair[1]
                    # really, really sloppy method for now
                    # JSON has some weird errors where functions don't match up to the jump addresses
                    # might be an issue with the r2 debugger, but this is just a sloppy work-around
                    if u'fail' in block_json:
                        try:
                            block_obj.fail = dict_block[block_json[u'fail']][0]
                        except KeyError:
                            continue

                    if u'jump' in block_json:
                        try:
                            block_obj.jump = dict_block[block_json[u'jump']][0]
                        except KeyError:
                            continue
                self.first = dict_block[blocks[000][u'offset']][0]
            #else:      
                #raise KeyError()
        #else: 
            #raise KeyError()

    def __str__(self):
        ret = ""
        node = self.first
        while node is not None:
            ret += "{}\n".format(node)
            if node.fail:
                node = node.fail
            else:
                node = node.jump

        return ret              

    def print_blocks(self, start):
        ret = ""
        i = 0
        if start:
            for inst in start.seq_inst:
                ret = "{}{}".format(ret, inst)
            
            if start.jump is not None:
                ret = "{}{}".format(ret, self.print_blocks(start.jump))
            if start.fail is not None:
                ret = "{}{}".format(ret, self.print_blocks(start.fail))
        return ret

    def gen_features(self, instr, blk):
        
        features = blk.gen_features(instr)    
        #features = blk.get_seq_inst()
       
        return features

    # targeted feature sensor creation, for use with known values
    def get_ctrl_feature(self, blk, sensor):
        features = {}
        if blk is not None:
            il = blk.seq_inst
            feature_visited.append(blk)
            for instr in il.items():
                for param in instr[1].params:
                    if sensor in features.keys():
                        if sensor in param:
                            features[ur"{}".format(param)].update(self.gen_features(instr, blk))
                    else:
                        if sensor in param:
                            features[sensor] = self.gen_features(instr, blk)
            # recurse through all later blocks to look for additional candidates
            if (blk.jump is not None and blk.jump not in feature_visited):
                features.update(self.get_ctrl_feature(blk.jump, sensor))
            if (blk.fail is not None and blk.fail not in feature_visited):
                features.update(self.get_ctrl_feature(blk.fail, sensor))    

        return features
    #returns list of features with address of sensors
    def get_feature(self, blk):
        features = {}
        global feature_visited
        #check item for LDA candidate, potential for sensor
        if blk is not None:
            il = blk.seq_inst
            feature_visited.append(blk)
            for instr in il.items():
                #if (((u'STA' in instr[1].opcode or u'STB' in instr[1].opcode or instr[1].opcode == u'LDA') or (instr[1].opcode == u'LDB')) and not ("al" in instr[1].params[0] or "bl" in instr[1].params[0]  or "ax" in instr[1].params[0] or "bx" in instr[1].params[0] or "xl" in instr[1].params[0] or "yl" in instr[1].params[0])):
                try:
                    for param in instr[1].params:
                     
                        if param not in features.keys() and "0x" in param and "#" not in param and "$" not in param:
                            if int(param, 16) < 0x6000:
                                features[ur"{}".format(param)] = self.gen_features(instr, blk)
                        elif param in features.keys():
                            features[ur"{}".format(param)].update(self.gen_features(instr, blk))
                        elif "$" in param:
                            hex_param = "0x{}".format(param[1:])  # remove $ from param
                            if hex_param not in features.keys():
                                features[ur"{}".format(hex_param)] = self.gen_features(instr, blk)
                            else:
                                features[ur"{}".format(hex_param)].update(self.gen_features(instr, blk))

                except IndexError as ie:
                    print ie
                    continue
            # recurse through all later blocks to look for additional candidates
            if (blk.jump is not None and blk.jump not in feature_visited):
                features.update(self.get_feature(blk.jump))
            if (blk.fail is not None and blk.fail not in feature_visited):
                features.update(self.get_feature(blk.fail))
        
        return features

class function:
    base_addr = 0x0 # address of the function
    json = ""      # json representation of function pointed to
    dot = ""       # dot representation of function pointed to

    def __init__(self, base_addr, cfg):
        self.base_addr = hex(base_addr)
        self.children = {}
        self.parents = {}
        self.cfg = cfg

    def __str__(self):
        
        ret = "{}\n".format(self.base_addr)
        for child in self.children.values():
            ret += "\t{}".format(child)
        return ret

    def push_child(self, func):
        self.children[func.base_addr] = func

    def get_single_feature(self, addr):
        return self.cfg.get_feature()

    def get_features(self):
        global feature_visited
        feature_visited = list()
        return self.cfg.get_feature(self.cfg.first)

    def get_ctrl_features(self, sensor):
        global feature_visited
        feature_visited = list()
        return self.cfg.get_ctrl_feature(self.cfg.first, sensor)

# locates the reset vector address from a valid M7700 binary
# using a currently open radare2 session
def get_rst(r2):
    r2.cmd("s 0xfffe")     # seek to the address for the reset vector (const for all of our binaries)
    logging.debug("R2 Command used: 's 0xfffe'")

    big_endian = str(r2.cmd("px0")) # print last two bytes of rst vector
    logging.debug("R2 Command used: 'px0'")

    rst = 0x0
    
    if big_endian:
        rst = int("{}{}".format(big_endian[2:4], big_endian[:2]), 16) # flip endianness of last two bytes
        logging.debug("rst vector address found at: 0x{:04x}".format(rst))
    else:
        logging.debug("ERR - reset vector search failed")

    return rst

# Helper function for recursive_parse_func
# grabs all child function calls from a function analysis in R2
def get_children(child_str):
    p = ur"JSR.*[^$](0x[0-9a-fA-F]{4})" # grab unrecognized funcs
    children = re.findall(p, child_str)
    p1 = ur"JSR.*fcn.0000([0-9a-fA-F]{4})"
    ch2 = re.findall(p1, child_str)
    children.extend(ch2) # grab recognized funcs

    int_children = list()
    for child in children:
        try:    
            int_children.append(int(child, 16))
        except TypeError:
            print (child)
    del children
    return int_children

# helper function for recursive parse func
# popluates 
def populate_cfg(addr, func_json):
    
    #json_obj = json.loads('{}'.format(func_json.decode('utf-8', 'ignore').encode('utf-8')), strict=True, object_pairs_hook=collections.OrderedDict)
    json_obj=json.loads(unicode(func_json, errors='ignore'), strict=False, object_pairs_hook=collections.OrderedDict)
    cfg = CFG(json_obj)
    return cfg

def func_parse_str(func_str):
    ret = []
    fs = func_str.splitlines()
    for line in fs:
        try:
            addr = int(line[:10], 16)
        except TypeError:
            continue
        if addr and addr >= 36864:
            ret.append(addr)
    return ret
    
# Creates an array of hashed features representing the instruction grams of each block within a function
def grab_features(func, visited):

    func_dict = {}

    if func in visited:
        return func_dict

    func_dict[ur"{}".format(func.base_addr)] = ur"{}".format(get_signature(func.cfg.first, []))
    visited.append(func)

    #for child in func.children.values():
    #    func_dict.update(grab_features(child, visited))

    return func_dict

# return a list of hash values for an entire function
def get_signature(block, visited):

    result = []
    if block is None or block in visited: # Ignore blocks we've already resited
        return result
    
    result.extend(block.get_seq_inst())
    #result.extend(block.ret_instruct_list())

    visited.append(block)

    if block.jump is not None:
        result.extend(get_signature(block.jump, visited))

    if block.fail is not None:
        result.extend(get_signature(block.fail, visited))

    return result

def get_json(feature_dict):
          
    return OrderedDict(json.dumps(feature_dict)) 

# helper function to check if a string is a hex string or not
def isHex(num): 
    try:
        int (num, 16)
        return True
    except ValueError:
        return False

def load_sensors(fn, sensor_list):

    ra2 = r2pipe.open(fn, ["-2"])

    if (ra2):
        
        ra2.cmd("e asm.arch=m7700")
        ra2.cmd("e anal.limits=true")
        ra2.cmd("e anal.from=0x9000")
        ra2.cmd("e anal.to=0xffd0")
        #ra2.cmd("e anal.hasnext=true")
        ra2.cmd("0x93c1")
        ra2.cmd("aaa")
        sensor_obj = {}

        for sensor in sensor_list:
            #print sensor
            sensor_obj[sensor] = [] # declare a list at each sensor value

            for sensor_addr in sensor_list[sensor]: # populate the list with the func disassembly
                ra2.cmd("s 0x{:04x}".format(int(sensor_addr, 16))) 
                ra2.cmd("aa")
                #ra2.cmd("sf.")
                #addr = ra2.cmd("s")
                if sensor_addr not in visited.keys():
                    fcn_obj = function(int(sensor_addr, 16), populate_cfg(int(sensor_addr, 16), ra2.cmd("agj")))
                    sensor_obj[sensor].append(fcn_obj) # create a function
                    visited[sensor_addr] = fcn_obj
                else:
                    sensor_obj[sensor].append(visited[sensor_addr])

        ra2.quit()
    else:
        print "Radare couldn't open {}".format(fn)
    
    return sensor_obj

def get_sensor_val(val, control, test):

    sensor = "0x0000" # default value if not found
    control_sensor = sensor_values[val]

    control_features = control.get_ctrl_features(control_sensor)
    test_features = test.get_features()
    sensor_feature = {}

    #print ("val {} control {} test {}".format(val, control, test))

    try:
        sensor_feature = control_features[ur"{}".format(control_sensor)]
    except KeyError:
        print "Error in key {}".format(control_sensor)
        return sensor

    i = 0
    largest = 0
    for addr, feature in test_features.iteritems():
        
        i = (jaccard(feature.items(), sensor_feature.items()))
        
        if i > largest:
            largest = i
            sensor = addr 
                
        i = 0
        
    return sensor

def jaccard(a, b):
    c = set(a).intersection(set(b))
    return float(len(c)) / (len(a) + len(b) - len(c))

# Uses a given sensor function address and its matching candidate address
# to try and find the value of the sensor in the analyzed candidate
def find_sensors(control_func_addr, test_func_addr):
    func_sensors = {}

    for val in control_func_addr:
        print val
        z = itertools.izip(control_func_addr[val], test_func_addr[val])

        for control, test in z:

            if func_sensors.has_key(val):
                func_sensors[val].append(get_sensor_val(val, control, test))
            else:
                func_sensors[val] = [get_sensor_val(val, control, test)]

        print func_sensors[val]

    return func_sensors

def main ():
    # set up the parser first
    # default parser args - filename, opens file for JSON parsing 
    # can also output JSON file as a .DOT file, or pull in a ROM and call R2 
    parser = argparse.ArgumentParser(description='Import and process M7700 JSON Graph files.')

    parser.add_argument('filename', metavar='filename', nargs='?', default='/home/greg/Documents/git/PySensorParser/94_test.json', type=str, 
                   help='M7700 ROM file for parsing')

    # parser.add_argument('-o', '--output', action='store_true',
    #                help='Output M7700 rom to file')

    logging.basicConfig(filename='log_filename.txt', level=logging.DEBUG)

    args = parser.parse_args()
    control_file = "/home/greg/Documents/ROMs/EG33/USDM/722527-1993-USDM-SVX-EG33.bin"
    jsons = {}

    control_cfg = load_sensors(control_file, sensors)

    json_file = open(args.filename, 'r')

    # compare each infile to the control file
    if json_file is not None:
        
        print("Opening file: {}".format(json_file))
        # analyze the ROM's functions
        json_string = u"{}".format(json_file.read())
        func_list = json.loads(json_string)
        jsons = {}
        
        for fn in func_list:
            # need a more elegant way to path to the files than this
            sensor_list = load_sensors("/home/greg/Documents/ROMs/EG33/USDM/{}".format(fn), func_list[fn])

            # output format - each filename will have a list like the control list above
            jsons[fn] = find_sensors(control_cfg, sensor_list)

        # attempt to find matching function for each value in the control_cfg

        with open('file.json', 'w') as out:
            json.dump(jsons, out, indent=4, sort_keys=True)
            out.close()

# start
if __name__ == '__main__':
    main()