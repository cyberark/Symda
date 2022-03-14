from __future__ import print_function
import frida
import sys
import sys
import pathlib
from ctypes import *
from capstone import *
from symbol_parser import get_symbol_table_for_binary
import json
import logging

# Add to the list below the functions you would like to hook
FUNCTION_LIST = [
    "KERNELBASE!DeviceIoControl",
]

SYMBOL_TABLE = {}

def load_file_symbols_wrapper(receved_obejct):
    result = {"ok_status": True, "error": "", "functions_in_symbol": 0}

    try:
        result["functions_in_symbol"] = load_file_symbols(receved_obejct["module"]["path"], int(receved_obejct["module"]["base"], 0))
    except Exception as e:
        result["ok_status"] = False
        result["Error"] = str(e)

    return result

def load_file_symbols(path, base):
    symbol_table = get_symbol_table_for_binary(path, base_addr=base)
    SYMBOL_TABLE[path] = symbol_table
    return len(symbol_table.keys())

def resolve_symbol_wrapper(receved_obejct):
    return resolve_symbol(receved_obejct["functionName"], receved_obejct["module"]["path"], receved_obejct["module"]["base"])

def resolve_symbol(function_name, path, base):
    if path not in SYMBOL_TABLE:
        load_file_symbols(path, base)
    symbol_table = SYMBOL_TABLE[path]
    addr = 0

    for symbol_entry in symbol_table:
        decoded_symbol_entry = symbol_entry.decode("utf-8")
        if function_name in decoded_symbol_entry or decoded_symbol_entry in function_name:
            addr = symbol_table[symbol_entry][0]
            break
    return addr

def resolve_function_name_wrapper(receved_obejct):
    return resolve_function_name(receved_obejct["pointerList"])

def resolve_function_name(pointer_list):
    for resolve_func_dict in pointer_list:
        value = pointer_list[resolve_func_dict]
        # If the function name resolved -> pass
        resolved_name = ""
        resolved_offset = float('inf')
        if value != "":
            continue
        
        for symbol_entry in SYMBOL_TABLE:
            image_name = symbol_entry.split("\\")[-1].split(".")[0] # Gets the image name
            for function_entry in SYMBOL_TABLE[symbol_entry]:
                base_func = SYMBOL_TABLE[symbol_entry][function_entry][0] # Address
                # We are greedy here, we look for the function that has the lowest offset and it's in our module we 
                if int(resolve_func_dict, 0) >= base_func and int(resolve_func_dict, 0) - base_func < resolved_offset:
                    resolved_offset = int(resolve_func_dict, 0) - base_func
                    resolved_name = "{}!{}".format(image_name, function_entry.decode())
        if resolved_offset != float('inf'):
            pointer_list[resolve_func_dict] = "{} + {}".format(resolved_name, hex(resolved_offset))
    return pointer_list

def on_message(message, data):
    global script
    logger = logging.getLogger()
    if message["type"] == "error":
        logger.error("Error - {}".format(message["stack"]))
        return
    receved_obejct = json.loads(message["payload"])
    if "log" in receved_obejct.keys():
        logger.info(receved_obejct['payload'])
        return
    if receved_obejct["action"] == "resolve_pointer_name":
        result = resolve_symbol_wrapper(receved_obejct)
    elif receved_obejct["action"] == "resolve_functions":
        result = resolve_function_name_wrapper(receved_obejct)
    elif receved_obejct["action"] == "load_file_symbols":
        result = load_file_symbols_wrapper(receved_obejct)

    script.post({"type": "input", "payload": result})

def main(target_process):
    global script
    parent_folder = str(pathlib.Path(__file__).parent.resolve())
    logging.basicConfig(filename=parent_folder+r'\\run.log', encoding='utf-8', level=logging.DEBUG)
    logger = logging.getLogger()
    #logger.addHandler(logging.FileHandler('run.log', 'a'))
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    # set a format which is simpler for console use
    formatter = logging.Formatter('')
    # tell the handler to use this format
    console.setFormatter(formatter)
    # add the handler to the root logger
    logger.addHandler(console)

    session = frida.attach(target_process)
    script_content = None
    with open(parent_folder + r"\\GenericFridaJavascript.js", "r") as fi:
        script_content = fi.read()
    script_content = script_content.replace("FUNCTION_LIST", str(FUNCTION_LIST))
    script = session.create_script(script_content)
    script.on('message', on_message)
    script.load()
    logging.info("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        logging.info("Usage: %s <PID>" % __file__)
        sys.exit(1)

    try:
        target_process = int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]
    main(target_process)