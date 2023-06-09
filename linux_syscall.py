# Script to add comments to linux syscalls.  Supports ARM, AARCH64, x86, x64.
# @Denis Patenaude
# @category Syscall_linux_comments
# @keybinding
# @menupath
# @toolbar


import sys
import os
import json


# FUNCTIONS
def parse_languageid(program):
    """ Takes language ID parses it. Returns associated register(list), json filename, and language """

    json_file_dict = {'ARM': 'arm.json', 'AARCH64': 'arm64.json', 'x86': 'x86.json', 'x64': 'x64.json'}
    language_register_dict = {'ARM': ['r7'], 'AARCH64': ['x8'], 'x86': ['EAX'], 'x64': ['RAX', 'EAX']}
    language_id = str(program.getLanguageID()).split(':')  # example lang_id (split) ['ARM', 'LE', '32', 'v8']
    processor = language_id[0]
    bits = language_id[2]

    # Build exceptions as they are found loading binaries in Ghidra.
    # Ghidra x86:LE:64:default
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
    """converts json file to dictionary.  Returns dictionary"""
    new_dict = {}
    with open(syscall_file) as json_file:
        data = json.load(json_file)
        for element in data:
            key = element['return']
            value = element['name']
            new_dict[key] = value
    return new_dict


def arm_oabi_to_arm_eabi(syscall_op):
    """ oabi used swi 0x900000 + syscall.  Returns eabi syscall string """
    syscall_op = int(syscall_op, 16)
    eabi = hex(syscall_op - 0x900000)
    return eabi


def find_syscall_name(new_dict, syscall_value):
    """ Mapa syscall hex value to syscall name. Returns syscall name """
    try:
        syscall_name = new_dict[syscall_value]
    except KeyError:
        syscall_name = 'unknown'
    return syscall_name


def determine_and_clean_operand_type(operands, address, language, oabi=False):
    """ Parses operands for syscall strings to determine if immediate value, pointer or other.
    Also formats hex values below 0x0A that only have a length of 1 I.E. (0x0) to (0x00) to adhere
    to the format in the json files by calling function format_immediate_value()
    Returns tuple with 'immediate' for immediate value, 'pointer' for pointer, 'other' and clean_key/None. """
    # Convert operands object to string and split
    if not oabi:
        operands_list = str(operands).split(',')
        if len(operands_list) > 2:
            print("\nOperand length greater than 2. Please review manually.")
            print ("{} at address {}\n").format(operands, address)
        # else if only 1 operand
        else:
            # Check first character of string to see if prepended with '#'
            if '#' == operands_list[1][0:1]:
                # check length of hex value.  Prepend 0 if length is 1 to match json file.
                clean_key = format_immediate_value(operands_list[1])
                return 'immediate', clean_key
            elif '0x' == operands_list[1][0:2]:
                # check length of hex value.  Prepend 0 if length is 1 to match json file.
                clean_key = format_immediate_value(operands_list[1])
                return 'immediate', clean_key
            # if pointer that needs to be dereferenced
            elif '[' == operands_list[1][0:1]:
                print('\n**** This value may need to be dereferenced manually. TODO for next version ****\n')
                return 'pointer', None
            else:
                return 'other', None
    elif oabi:
        operand = str(operands).split()[1]
        syscall_base = hex(0x90000)
        # old ARM syntax is 0x900000 + syscall. Check to if that is the case.
        if int(operand, 16) >= int(syscall_base, 16):
            key = arm_oabi_to_arm_eabi(operand)
            clean_key = format_immediate_value(key)
            return 'immediate', clean_key
        else:
            print('\nExpected at least {} as syscall base.  Got {} instead.\n').format(syscall_base, operand)


def create_comments(current_address, op_type, syscall_name, hex_num):
    """ Modifies EOL comment based on syscall mapping. """
    # checks if comment exists, appends if so
    # TODO figure out how to delete previous comment or replace
    comment_exists = getEOLComment(current_address)
    previous_unknown_comment = 'syscall: Unable to determine. Review manually'
    syscall_partial_comment = 'syscall: 0x'
    # if immediate value
    if op_type == 'immediate':
        if comment_exists is not None:
            original_comment = getEOLComment(current_address)
            # if already commented, pass
            if syscall_partial_comment in original_comment:
                pass
            # if previous attempt was unable but new future code functionality allows it, overwrite previous comment
            elif previous_unknown_comment in original_comment:
                new_comment = 'syscall: ' + hex_num + ' - ' + syscall_name
                setEOLComment(current_address, new_comment)
            else:
                prepended_comment = 'syscall: ' + hex_num + ' - ' + syscall_name
                new_comment = prepended_comment + ' - ' + original_comment
                setEOLComment(current_address, new_comment)
        else:
            # if there's not previous comment, add new comment
            new_comment = 'syscall: ' + hex_num + ' - ' + syscall_name
            setEOLComment(current_address, new_comment)
    # If not immediate value
    else:
        # if it's not an immediate value we don't deal with it at this time. Maybe later.
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

def build_previous_instruction_list(instruction):
    prev_list = []
    instruction_addr = instruction.getAddress()
    prev_instruction = getInstructionAt(instruction_addr)
    for i in range(4):
       prev_instruction = prev_instruction.getPrevious()
       prev_list.append(str(prev_instruction))
    return prev_list


def main():
    program = getCurrentProgram()
    af = program.getAddressFactory()
    func = getFirstFunction()
    start_addr = af.getAddress(str(func.getEntryPoint()))
    instruction = getInstructionAt(start_addr)

    # determine architecture using languageID.
    lang_id = parse_languageid(program)
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
        # valid syscall mnemonic strings and operands
        valid_mnemonic = {'swi': ['0x0', '0x900000'], 'svc': ['0'], 'int': ['0x80'], 'syscall': [None]}

        while instruction is not None:
            mnemonic = instruction.getMnemonicString()
            # normalize mnemonic to lowercase
            mnemonic = mnemonic.lower()
            current_address = instruction.getAddress()
            # Initial instruction might not have a previous operand, so we try except
            try:
                previous_operands = instruction.getPrevious()
                previous_address = previous_operands.getAddress()
            except AttributeError:
                instruction = instruction.getNext()
                continue
            if mnemonic in valid_mnemonic:
                for operand in valid_mnemonic[mnemonic]:
                    # if anything but swi and syscall
                    if mnemonic != 'swi' and mnemonic != 'syscall':
                        if operand in str(instruction).split()[1]:
                            # if multiple registers are possible
                            for register in registers:
                                if register in str(previous_operands):
                                    op_type = determine_and_clean_operand_type(previous_operands, previous_address,
                                                                               language, oabi=False)
                                    try:
                                        if op_type[0] == 'immediate':  # if immediate value.
                                            syscall_hex_str = op_type[1]
                                            syscall_name = find_syscall_name(syscall_dictionary, syscall_hex_str)
                                            create_comments(current_address, op_type[0], str(syscall_name), syscall_hex_str)
                                    except TypeError:
                                        continue
                                    
                    elif mnemonic == 'swi':
                        # if '0x0'
                        if operand in str(instruction).split()[1]:
                            # if multiple registers are possible
                            previous_operand_list = build_previous_instruction_list(instruction)
                            for prev_operations in previous_operand_list:
                                for register in registers:
                                    if register in str(prev_operations):
                                        op_type = determine_and_clean_operand_type(prev_operations, previous_address, #TODO mirror this if it works
                                                                               language, oabi=False)
                                        try:
                                            if op_type[0] == 'immediate':  # if immediate value.
                                                syscall_hex_str = op_type[1]
                                                syscall_name = find_syscall_name(syscall_dictionary, syscall_hex_str)
                                                create_comments(current_address, op_type[0], str(syscall_name), syscall_hex_str)
                                        except TypeError:
                                            continue

                        else:    # else it's oabi.  Does not use register
                            actual_operand = str(instruction).split()[1]
                            syscall_base = hex(0x90000)
                            # confirm that value is greater than or equal to 0x900000
                            if int(actual_operand, 16) >= int(syscall_base, 16):
                                op_type = determine_and_clean_operand_type(instruction, current_address,
                                                                           language, oabi=True)
                                try:
                                    if op_type[0] == 'immediate':  # if immediate value.
                                        syscall_hex_str = op_type[1]
                                        syscall_name = find_syscall_name(syscall_dictionary, syscall_hex_str)
                                        create_comments(current_address, op_type[0], str(syscall_name), syscall_hex_str)
                                except TypeError:
                                    continue
                                
                    elif mnemonic == 'syscall':
                        # if multiple registers are possible. I.E. RAX and EAX
                        for register in registers:
                            if register in str(previous_operands):
                                op_type = determine_and_clean_operand_type(previous_operands, previous_address,
                                                                           language, oabi=False)
                                try:
                                    if op_type[0] == 'immediate':  # if immediate value.
                                        syscall_hex_str = op_type[1]
                                        syscall_name = find_syscall_name(syscall_dictionary, syscall_hex_str)
                                        create_comments(current_address, op_type[0], str(syscall_name), syscall_hex_str)
                                except TypeError:
                                    continue
                    else:
                        op_type = ('other', None)
                        syscall_name = None
                        syscall_hex_str = None
                        create_comments(current_address, op_type[0], str(syscall_name), syscall_hex_str)
                    
                    #if op_type[0] == 'immediate':  # if immediate value.
                    #    syscall_hex_str = op_type[1]
                    #    syscall_name = find_syscall_name(syscall_dictionary, syscall_hex_str)
                    #    create_comments(current_address, op_type[0], str(syscall_name), syscall_hex_str)
                            
            
            instruction = instruction.getNext()
    else:
        print("\n {} is not supported.").format(language)
        sys.exit(1)


if __name__ == '__main__':
    main()
