# Script to add comments to linux syscalls.  Supports arm, arm64, x86, x64.  Currently tested: ARM
# @Denis Patenaude
# @category _NEW_
# @keybinding
# @menupath
# @toolbar

# version 0.2 April 11 10:03 A.M. comments work for ARM32.  Still need to cleanup print statements
# created function for swi 0x900000 not implemented in code yet.
# TODO:  Add special case where swi 0x900000 <- substract 90000? hex to get syscall

###How to derefence pointers for registers
###go back up to 3 instructions (in the future). Worth it?


'''
Source of syscall json files: https://syscall.sh/
To download via API:
curl -X 'GET'   'https://api.syscall.sh/v1/syscalls1/arm'   -H 'accept: application/json' > arm.json
curl -X 'GET'   'https://api.syscall.sh/v1/syscalls1/arm64'   -H 'accept: application/json' > arm64.json
curl -X 'GET'   'https://api.syscall.sh/v1/syscalls1/x86'   -H 'accept: application/json' > x86.json
curl -X 'GET'   'https://api.syscall.sh/v1/syscalls1/x64'   -H 'accept: application/json' > x64.json
'''

# Not needed within the ghidra framework but kept for reference when using python console to test stuff.
import ghidra
# from ghidra.program.flatapi import FlatProgramAPI as FA

from __main__ import *
import os
import json


### FUNCTIONS###
def arm_oabi_to_arm_eabi(syscall_op):
    """ older abi used swi 0x900000 + syscall.  Returns eabi syscall """
    syscall_op = int(syscall_op, 16)

    eabi = hex(oabi - 0x900000)
    return eabi


def json_to_dict(syscall_file):
    new_dict = {}
    with open(syscall_file) as json_file:
        data = json.load(json_file)
        for element in data:
            key = element['return']
            value = element['name']
            new_dict[key] = value
    return new_dict


def find_syscall_name(new_dict, reg_hex_value):
    """ map syscall hex value to syscall name and return tuple with key, value """
    try:
        sys_name = new_dict[reg_hex_value]
    except KeyError:
        sys_name = 'unknown'

    return sys_name


def parse_languageID(program):
    """ Takes language ID parses it and returns register used for syscall value based on architecture
     and json file name for conversion to dictionary """
    language_id = str(program.getLanguageID()).split(':')  # example lang_id (split) ['ARM', 'LE', '32', 'v8']
    language = language_id[0]
    json_file_list = ['arm.json', 'arm64.json', 'x86.json', 'x64.json']

    if language == 'ARM':
        reg = 'r7'
        json_file = json_file_list[0]
    elif language == 'AARCH64':
        reg = 'x8'
        json_file = json_file_list[1]
    elif language == 'x86':
        reg = 'eax'
        json_file = json_file_list[2]
    elif language == 'x64':
        reg = 'rax'
        json_file = json_file_list[3]
    else:
        reg = None
        json_file = None

    if reg is None or json_file is None:
        print("\nCould not identify language.  Currently supported languages: ARM, AARCH64, x86, x64")
        exit(1)

    return reg, json_file, language


def parse_operands(operands, address):
    """ parses operands for syscall strings to determine if immediate value, pointer or other.
    Returns 'immediate' for immediate value, 'pointer' for pointer, 'other' for other. """
    # Convert operands object to string and split
    operands_list = str(operands).split(',')
    if len(operands_list) > 2:
        print('\noperand length greater than 2. No comments added.  Please review manually.')
        print'{} at address {}\n'.format(operands, address)
    # else if only 1 operand
    else:
        # if immediate value contains #
        if '#' in operands_list[1]:
            clean_key = clean_immediate_value(operands_list[1])
            return 'immediate', clean_key
        # if pointer that needs to be dereferenced
        elif '[' in operands_list[1]:
            print('\n**** This value may need to be dereferenced manually. TODO for next version ****\n')
            return 'pointer', None
        else:
            return 'other', None


def create_comments(current_address, hex_num, syscall_name, operand_len):
    """ modify EOL comment based on syscall mapping """
    # operand_len added for future coding.  Determine what comment to put when not a single mov into register.

    # checks if comment exists, appends if so
    comment_exists = getEOLComment(current_address)
    if comment_exists is None:
        new_comment = 'syscall: ' + hex_num + ' - ' + syscall_name
        setEOLComment(current_address, new_comment)
    else:
        original_comment = getEOLComment(current_address)
        if 'syscall: ' in original_comment:
            pass
        else:
            appended_comment = 'syscall: ' + hex_num + ' -  ' + syscall_name
            new_comment = original_comment + ' - ' + appended_comment
            setEOLComment(current_address, new_comment)


def clean_immediate_value(hex_string):
    """Some low hex values are a single hex character but the dictionary key is expecting 2 hex characters.
    I.E. Ghidra #0x0, dict key: 0x00 returns formatted hex value."""

    split_string = '0x'
    hex_string_list = hex_string.split(split_string)
    hex_value = hex_string_list[1]
    # If only single character prepend 0
    if len(hex_value) == 1:
        new_hex_string = '0' + hex_value
        syscall_hex_key = '0x' + new_hex_string
    else:
        syscall_hex_key = '0x' + hex_value

    return syscall_hex_key


###CODE SECTION###

program = getCurrentProgram()
af = program.getAddressFactory()
func = getFirstFunction()
start_addr = af.getAddress(str(func.getEntryPoint()))
instruction = getInstructionAt(start_addr)

# determine architecture using languageID.
lang_id = parse_languageID(program)

# register value depends on language ID of binary
register = lang_id[0]
# json filename to use for language
json_filename = lang_id[1]

language = lang_id[2]

# syscall dir expected in ghidra directory
syscall_dir = os.path.join(os.getcwd(), 'syscall')
full_path_file = os.path.join(syscall_dir, json_filename)

# convert json file to dictionary
syscall_dictionary = json_to_dict(full_path_file)
# valid mnemonic strings
valid_mnemonic = ['swi', 'svc', 'int', 'syscall']
valid_languages = ['ARM', 'AARCH64', 'x86', 'x64']

# Check for existence of syscall directory.  Print message and exit if directory does not exist
if os.path.isdir(syscall_dir) is False:
    print('\n **** Please create "syscall" directory in {} and copy json files there. ****').format(os.getcwd())
    exit(1)
else:
    #  Check for existence of json file.  Print message and exit if file does not exist
    if os.path.exists(full_path_file) is False:
        print('\n ****  Cannot find or access "{}".  Please check that "{}" is in "{}" directory ****\n').format(
            json_filename, json_filename, syscall_dir)
        exit(1)

while instruction is not None:
    mnemonic = instruction.getMnemonicString()
    current_address = instruction.getAddress()
    previous_address = instruction.getPrevious()
    previous_operands = getInstructionAt(previous_address)

    if mnemonic in valid_mnemonic:
        if language in valid_languages:
            if language == 'ARM' or language == 'AARCH64':
                syscall_list = str(instruction).split(' ')
                #TODO
                old_syscall_base = int(syscall_list[1],16)
                if syscall_list[1]
                ##TO DO if mnemonic is swi we need to check that it's not 0x0 and that it's greater than or = to 900000
                if register in str(previous_operands):
                    op_info_clean_key = parse_operands(previous_operands, previous_address)  # parse_operands function call

                    try:
                        if op_info_clean_key[0] == 'immediate':  # if immediate value.
                            syscall_hex = clean_immediate_value(op_info_clean_key[1], language)

                            syscall_name = find_syscall_name(syscall_dictionary, syscall_hex)

                            create_comments(current_address, syscall_hex, syscall_name,
                                            op_info_clean_key[0])  # create comment function call
                        else:  # if anything but 'immediate' value simply append to list and report count at end of script #TODO
                            syscalls1_not_reg_previous.append(str(current_address))
                    except TypeError as e:
                        print(op_info_clean_key)
                        print(previous_operands)
                        continue
    instruction = instruction.getNext()
