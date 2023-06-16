Purpose

I wrote this python script to automate the commenting of syscalls in stripped linux elf binaries to help with the
initial static analysis.

Limitations

At the moment;
- it only supports the following processors: ARM, AARCH64, x86, and x64
- it only comments immediate syscall values.  I.E.  No dereference of pointers, etc.
- Now check 5 previous operations for valid register immediate value

TO DO

- Add reporting on instructions found but not commented so they can be manually reviewed.

Dependencies

- Ghidra
- curl (optional)

Setup

- cd to ghidra
	cd ghidra_xx.x.x_PUBLIC/
- create directory syscall
	mkdir syscall
- download or copy (if previously downloaded) the json files to the syscall directory
	Download the syscall json files from https://syscall.sh/.  See below for details
	on how to use curl to create the json file.

	The source of syscall json files is  https://syscall.sh/

	To download via API:

	curl -X 'GET' \
	'https://api.syscall.sh/v1/syscalls/arm' \
	-H 'accept: application/json' > arm.json

	curl -X 'GET' \
	'https://api.syscall.sh/v1/syscalls/arm64' \
	-H 'accept: application/json' > arm64.json

	curl -X 'GET' \
	'https://api.syscall.sh/v1/syscalls/x86' \
	-H 'accept: application/json' > x86.json

	curl -X 'GET' \
	'https://api.syscall.sh/v1/syscalls/x64' \
	-H 'accept: application/json' > x64.json


- Add script in Ghidra

From the top menu select;
- Window > Script Manager
- In the Ghidra Script Manager click the "Script Directories" icon in the toolbar and add the checked out repository as a path.
  The script will appear in the "Syscall_linux_comments" category.

Usage

- Navigate to the "Syscall_linux_comments" category
- Right click on "linux_syscall.py"
- Select "Run Script"

- Any information or message will appear in the Console window.

Viewing comments

The EOL (End of line) comments can be viewed by going to the top menu
and selecting ->  Window > Comments

The comments have the following syntax: "syscall:" <operand> - <syscall name>
I.E.  syscall: 0x29 - socket

If unable to determine the syscall.  The following comment will appear:
"syscall: Unable to determine. Review manually"





