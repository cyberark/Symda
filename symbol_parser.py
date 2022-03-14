from ctypes import *
from ctypes.wintypes import *
import pathlib
import sys

# Definations

class SYMBOL_INFO(Structure):
    _fields_ = [
        ('SizeOfStruct', c_uint32),
        ('TypeIndex',    c_uint32),
        ('Reserved',     c_uint64*2),
        ('Index',        c_uint32),
        ('Size',         c_uint32),
        ('ModBase',      c_uint64),
        ('Flags',        c_uint32),
        ('Value',        c_uint64),
        ('Address',      c_uint64),
        ('Register',     c_uint32),
        ('Scope',        c_uint32),
        ('Tag',          c_uint32),
        ('NameLen',      c_uint32),
        ('MaxNameLen',   c_uint32),
        ('Name',         c_char * (2000 + 1))
    ]

class GUID(Structure):
    _fields_ = [
        ("Data1",   DWORD),
        ("Data2",   WORD),
        ("Data3",   WORD),
        ("Data4",   BYTE * 8),
]

class IMAGEHLP_MODULEW64 (Structure):
    _fields_ = [
        ("SizeOfStruct",    DWORD),
        ("BaseOfImage",     c_uint64),
        ("ImageSize",       DWORD),
        ("TimeDateStamp",   DWORD),
        ("CheckSum",        DWORD),
        ("NumSyms",         DWORD),
        ("SymType",         DWORD),
        ("ModuleName",      WCHAR * 32),
        ("ImageName",       WCHAR * 256),
        ("LoadedImageName", WCHAR * 256),
        ("LoadedPdbName",   WCHAR * 256),
        ("CVSig",           DWORD),
        ("CVData",          WCHAR * (MAX_PATH * 3)),
        ("PdbSig",          DWORD),
        ("PdbSig70",        GUID),
        ("PdbAge",          DWORD),
        ("PdbUnmatched",    BOOL),
        ("DbgUnmatched",    BOOL),
        ("LineNumbers",     BOOL),
        ("GlobalSymbols",   BOOL),
        ("TypeInfo",        BOOL),
        ("SourceIndexed",   BOOL),
        ("Publics",         BOOL),
    ]
PIMAGEHLP_MODULEW64 = POINTER(IMAGEHLP_MODULEW64)

NULL = 0x0

SYMBOL_PATH = "C:\\symbols;SRV*C:\\symbols*https://msdl.microsoft.com/download/symbols"

# Helper functions

def RaiseIfZero(result, func = None, arguments = ()):
    if not result:
        raise WinError()
    return result

def RaiseIfNotZero(result, func = None, arguments = ()):
    if result:
        raise WinError()
    return result

def enum_proc(info, size, param):
    #print("info - info->Name: {0} info->Address: {1}, info->Size: {2}, info->Tag: {3}".format(info.Name, hex(info.Address), info.Size, info.Tag))
    global function_from_symbols
    function_from_symbols[info.Name] = [info.Address, info.Size, info.Tag]

# dbghelp functions

def SymInitializeW(hProcess, user_search_path, f_invade_process=False):
    _SymInitializeW = windll.dbghelp.SymInitializeW
    _SymInitializeW.argtypes = [c_void_p, c_void_p, c_bool]
    _SymInitializeW.restype = int
    _SymInitializeW.errcheck = RaiseIfZero
    _SymInitializeW(hProcess, user_search_path, f_invade_process)

def SymLoadModuleEx(g_handle, module_path, base_addr=0):
    _SymLoadModuleEx = windll.dbghelp.SymLoadModuleEx
    _SymLoadModuleEx.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, c_int64, c_int32, c_void_p, c_int32]
    _SymLoadModuleEx.restype = c_uint64
    _SymLoadModuleEx.errcheck = RaiseIfZero
    return _SymLoadModuleEx(g_handle, NULL, module_path.encode("utf-8"), NULL, base_addr, 0, NULL, 0)

def SymUnloadModule64(h_process, base_of_dll):
    _SymUnloadModule64 = windll.dbghelp.SymUnloadModule64
    _SymUnloadModule64.argtypes = [c_uint64, c_uint64]
    _SymUnloadModule64.restype = c_bool
    _SymUnloadModule64.errcheck = RaiseIfZero
    return _SymUnloadModule64(h_process, base_of_dll)

def SymGetModuleInfoW(h_process, base_of_dll):
    _SymGetModuleInfoW = windll.dbghelp.SymGetModuleInfoW
    _SymGetModuleInfoW.argtypes = [c_void_p, c_uint64, POINTER(IMAGEHLP_MODULEW64)]
    _SymGetModuleInfoW.restype = c_bool
    _SymGetModuleInfoW.errcheck = RaiseIfZero
    module = IMAGEHLP_MODULEW64()
    module.SizeOfStruct = sizeof(module)
    _SymGetModuleInfoW(h_process, base_of_dll, byref(module))
    return module

def SymEnumSymbols(hProcess, BaseOfDll):
    SymEnumSymbolsCB = WINFUNCTYPE(None, SYMBOL_INFO, c_ulong, c_void_p)
    _enum_proc = SymEnumSymbolsCB(enum_proc)
    _SymEnumSymbols = windll.dbghelp.SymEnumSymbols
    _SymEnumSymbols.argtypes = [c_void_p, c_uint64, c_void_p, SymEnumSymbolsCB, c_void_p]
    _SymEnumSymbols.restype = c_bool
    _SymEnumSymbols.errcheck = RaiseIfZero
    return _SymEnumSymbols(hProcess, BaseOfDll, "*", _enum_proc, NULL)

def get_symbol_server(symbol_path):
    if symbol_path.find("SRV*") == -1:
        return symbol_path
    splited_path = symbol_path.split("SRV*")[1].split(";")
    return splited_path[0]

def get_symbol_table_for_binary(binary_path, symbol_path=SYMBOL_PATH, base_addr=0):
    global function_from_symbols
    function_from_symbols = {}
    SSRVOPT_GUIDPTR = 8
    g_handle = 0x403
    symsrv = CDLL(str(pathlib.Path(__file__).parent.resolve()) + "\\third_party\\debugging_tools\\symsrv.dll")

    ## symsrv ##
    # SymbolServerSetOptions
    SymbolServerSetOptions = symsrv.SymbolServerSetOptions
    SymbolServerSetOptions.argtypes = [c_void_p, c_uint64]
    SymbolServerSetOptions.restype = c_bool
    SymbolServerSetOptions.errcheck = RaiseIfZero
    # SymbolServerW
    SymbolServerW = symsrv.SymbolServerW
    SymbolServerW.argtypes = [c_void_p, c_wchar_p, c_void_p, DWORD, DWORD, c_void_p]
    SymbolServerW.restype = c_bool
    SymbolServerW.errcheck = RaiseIfZero
    # Init Sym
    SymInitializeW(g_handle, symbol_path)

    # Load module
    base_addr = SymLoadModuleEx(g_handle, binary_path, base_addr)
    # Load module info
    module = SymGetModuleInfoW(g_handle, base_addr)

    # Checks if the module PDB is loaded
    if module.LoadedPdbName == "":
        # Download Symbols
        pdb_out = create_unicode_buffer(512)
        SymbolServerSetOptions(SSRVOPT_GUIDPTR, True)
        file_name = create_unicode_buffer(module.ImageName.split("\\")[-1].split(".")[0] + ".pdb")
        SymbolServerW(get_symbol_server(symbol_path),  file_name, byref(module.PdbSig70), module.PdbAge, 0, byref(pdb_out))
        SymUnloadModule64(g_handle, base_addr)
        base_addr = SymLoadModuleEx(g_handle, binary_path, base_addr)
        module = SymGetModuleInfoW(g_handle, base_addr)

    # Enum symbols
    SymEnumSymbols(g_handle, base_addr)
    return function_from_symbols


def main(target_executable):
    symbol_table = get_symbol_table_for_binary(target_executable, base_addr=0)
    print(symbol_table)
    

if "__main__" == __name__:
    if len(sys.argv) != 2:
        print("Usage: %s <EXE or DLL path>" % __file__)
        sys.exit(1)
    target_executable = sys.argv[1]
    main(target_executable)