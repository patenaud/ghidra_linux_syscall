# Script to add comments to linux syscalls.  Supports ARM, AARCH64, x86, x64.
# @Denis Patenaude
# @category Syscall_linux_comments
# @keybinding
# @menupath
# @toolbar


import sys
import os
import json


### FUNCTIONS###
def parse_languageID(program):
    """ Takes language ID parses it. Returns associated register(list), json filename, and language """

    json_file_dict = {'ARM': 'arm.json', 'AARCH64': 'arm64.json', 'x86': 'x86.json', 'x64': 'x64.json'}
    language_register_dict = {'ARM': ['r7'], 'AARCH64': ['x8'], 'x86': ['EAX'], 'x64': ['RAX', 'EAX']}
    language_id = str(program.getLanguageID()).split(':')  # example lang_id (split) ['ARM', 'LE', '32', 'v8']
    processor = language_id[0]
    bits = language_id[2]

    #Build exceptions as they are found loading binaries in Ghidra.
    #Ghidra x86:LE:64:default
    if processor == 'x86' and bits == '64':
        language = 'x64'
        register = language_register_dict[language]
        json_file = json_file_dict[language]
    else:
        language = processor
        try:
            register = language_register_dict[language]
            json_file = json_file_dict[language]
        except KeyError as e:
            print("\nCould not identify language.  Currently supported languages: ARM, AARCH64, x86, x64\n")
            print(e)
            sys.exit(1)
    return register, json_file, language


def check_syscall_file_path(json_filename):
    """Check that syscall path and file exist. Print message and exit if path does not exist.  Returns full file path"""

    ghidra_dir = os.getcwd()
    syscall_dir = os.path.join(ghidra_dir, 'syscall')
    full_path_file = os.path.join(syscall_dir, json_filename)

    # Check for existence of syscall directory.  Print message and exit if directory does not exist
    if os.path.isdir(syscall_dir) is False:
        print('\n **** Please create "syscall" directory in {} and copy json files there. ****').format(ghidra_dir)
        sys.exit(1)
        #  Check for existence of json file.  Print message and exit if file does not exist
    elif os.path.exists(full_path_file) is False:
        print('\n ****  Cannot find or access "{}".  Please check that "{}" is in "{}" directory ****\n').format(
            json_filename, json_filename, syscall_dir)
        sys.exit(1)
    else:
        return full_path_file

def json_to_dict(syscall_file):
    new_dict = {}
    with open(syscall_file) as json_file:
        data = json.load(json_file)
        for element in data:
            key = element['return']
            value = element['name']
            new_dict[key] = value
    return new_dict

def arm_oabi_to_arm_eabi(syscall_op):
    """ older abi used swi 0x900000 + syscall.  Returns eabi syscall string """
    syscall_op = int(syscall_op, 16)
    eabi = hex(syscall_op - 0x900000)
    return eabi
def find_syscall_name(new_dict, syscall_value):
    """ map syscall hex value to syscall name. Returns syscall name """
    try:
        syscall_name = new_dict[syscall_value]
    except KeyError:
        syscall_name = 'unknown'
    return syscall_name

def determine_and_clean_operand_type(operands, address,language):
    """ parses operands for syscall strings to determine if immediate value, pointer or other.
    Returns 'immediate' for immediate value, 'pointer' for pointer, 'other'. """
    # Convert operands object to string and split
    operands_list = str(operands).split(',')
    if len(operands_list) > 2:
        print("\nOperand length greater than 2. No comments added.  Please review manually.")
        print "{} at address {}\n".format(operands, address)
    # else if only 1 operand
    else:
        if language == 'ARM':
            # Check first character of string to see if prepended with '#'
            if '#' in operands_list[1][0:1]:
                # check length of hex value.  Prepend 0 if length is 1 to match json file.
                clean_key = format_immediate_value(operands_list[1])
                # old ARM syntax is 0x900000 + syscall. Check to if that is the case.
                if int(clean_key, 16) >= (int(0x900000)):
                    # clean value by subtracting 0x900000, return eabi syscall value
                    clean_key = arm_oabi_to_arm_eabi(clean_key)
                return 'immediate', clean_key
        elif '0x' in operands_list[1][0:2]:
            # check length of hex value.  Prepend 0 if length is 1 to match json file.
            clean_key = format_immediate_value(operands_list[1])
            return 'immediate', clean_key
        # if pointer that needs to be dereferenced
        elif '[' in operands_list[1][0:1]:
            print('\n**** This value may need to be dereferenced manually. TODO for next version ****\n')
            return 'pointer', None
        else:
            return 'other', None


def create_comments(current_address, op_type, syscall_name=None, hex_num=None):
    """ modify EOL comment based on syscall mapping """
    # checks if comment exists, appends if so
    comment_exists = getEOLComment(current_address)
    # if immediate value
    if op_type == 'immediate':
        if comment_exists is not None:
            original_comment = getEOLComment(current_address)
            if 'syscall: ' in original_comment:
                pass
            else:
                appended_comment = 'syscall: ' + hex_num + ' -  ' + syscall_name
                new_comment = original_comment + ' - ' + appended_comment
                setEOLComment(current_address, new_comment)
        else:
            new_comment = 'syscall: ' + hex_num + ' - ' + syscall_name
            setEOLComment(current_address, new_comment)
    # If not immediate value
    else:
        new_comment = 'syscall: Unable to determine. Review manually'
        setEOLComment(current_address, new_comment)
def format_immediate_value(hex_string):
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

def build_stats():
    pass

def main():
    program = getCurrentProgram()
    af = program.getAddressFactory()
    func = getFirstFunction()
    start_addr = af.getAddress(str(func.getEntryPoint()))
    instruction = getInstructionAt(start_addr)

    # determine architecture using languageID.
    lang_id = parse_languageID(program)
    # register value (list)
    registers = lang_id[0]
    # json filename
    json_filename = lang_id[1]
    # language
    language = lang_id[2]
    valid_languages = ['ARM', 'AARCH64', 'x86', 'x64']

    if language in valid_languages:
        # Check that path and file exist. Return full file path if True.  Print message and exit if False.
        full_file_path = check_syscall_file_path(json_filename)
        # convert json file to dictionary
        syscall_dictionary = json_to_dict(full_file_path)
        # valid mnemonic strings
        valid_mnemonic = ['swi', 'SWI', 'svc', 'SVC', 'int', 'INT', 'syscall', 'SYSCALL']

        while instruction is not None:
            mnemonic = instruction.getMnemonicString()
            current_address = instruction.getAddress()
            previous_operands = instruction.getPrevious()
            previous_address = previous_operands.getAddress()

            if mnemonic in valid_mnemonic:
                # if multiple registers are possible. I.E. RAX and EAX
                for register in registers:
                    if register in str(previous_operands):
                        # determine op type.  Immediate, pointer, other
                        op_type = determine_and_clean_operand_type(previous_operands,
                                                                   previous_address, language)
                        try:
                            if op_type[0] == 'immediate':  # if immediate value.
                                syscall_hex_str = op_type[1]
                                syscall_name = find_syscall_name(syscall_dictionary, syscall_hex_str)
                                create_comments(current_address, op_type[0], str(syscall_name), syscall_hex_str)
                            else:
                                create_comments(current_address, op_type[0], str(syscall_name), syscall_hex_str)

                        except TypeError as e:
                            print(op_type)
                            print(previous_operands)
                            print(syscall_name)
                            continue
                    else:
                        continue
            instruction = instruction.getNext()
    else:
        print("You have to give a message saying that the language is not supported.  Try except? ")

if __name__ == '__main__':
    main()