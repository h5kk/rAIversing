import os
import sys
import platform
import ctypes
from ctypes import windll
import traceback

print("Python version:", sys.version)
arch = platform.architecture()[0]
print("Platform architecture:", arch)

if arch != "32bit":
    print("\nWARNING: Running on 64-bit Python. IDA modules require 32-bit Python.")
    print("Please install 32-bit Python 3.9 from: https://www.python.org/downloads/release/python-390/")
    print("Select: Windows x86 executable installer")
    sys.exit(1)

print("\nPython path:")
for path in sys.path:
    print(path)

print("\nTrying to import IDA modules...")

def check_dll_dependencies(dll_path):
    try:
        # Try to load the DLL
        dll = windll.LoadLibrary(dll_path)
        print(f"Successfully loaded {dll_path}")
        return True
    except Exception as e:
        print(f"Error loading {dll_path}: {str(e)}")
        
        # Try to get more details about missing dependencies
        try:
            import win32api
            missing = win32api.GetModuleFileName(None)
            print(f"Missing dependency might be related to: {missing}")
        except:
            pass
        
        # Check if the file exists and get its details
        if os.path.exists(dll_path):
            print(f"\nFile details for {dll_path}:")
            print(f"Size: {os.path.getsize(dll_path)} bytes")
            try:
                # Try to get binary type
                import win32file
                binary_type = win32file.GetBinaryType(dll_path)
                print(f"Binary type: {binary_type}")
            except:
                pass
        else:
            print(f"File does not exist: {dll_path}")
        
        return False

print("\nLoading dependencies...")
temp_dir = os.environ.get('TEMP_MODULES_DIR', '')
ida_dir = os.environ.get('IDA_DIR', '')

# First check Qt dependencies
qt_dlls = ['Qt5Core.dll', 'Qt5Gui.dll', 'Qt5Widgets.dll']
for dll in qt_dlls:
    dll_path = os.path.join(temp_dir, dll)
    print(f"\nChecking {dll}...")
    check_dll_dependencies(dll_path)

# Then check IDA DLLs
print("\nChecking IDA DLLs...")
ida_dll = os.path.join(temp_dir, 'ida.dll')
if not check_dll_dependencies(ida_dll):
    print(f"\nChecking if ida.dll exists: {os.path.exists(ida_dll)}")
    print(f"Full path tried: {ida_dll}")
    
    # List all DLLs in the directory
    print("\nAvailable DLLs in directory:")
    for file in os.listdir(temp_dir):
        if file.endswith('.dll'):
            full_path = os.path.join(temp_dir, file)
            print(f"- {file} ({os.path.getsize(full_path)} bytes)")

# Check idapython3.dll
idapython_dll = os.path.join(temp_dir, 'idapython3.dll')
if os.path.exists(idapython_dll):
    print(f"\nChecking idapython3.dll...")
    check_dll_dependencies(idapython_dll)

try:
    import ida_idaapi
    print("\nSuccessfully imported ida_idaapi")
    print("Module location:", ida_idaapi.__file__)
except ImportError as e:
    print(f"\nImport error: {str(e)}")
    
    # Check for _ida_idaapi.pyd
    pyd_files = [f for f in os.listdir(temp_dir) if f.endswith('.pyd')]
    print(f"Found .pyd files: {pyd_files}")
    
    idaapi_pyd = os.path.join(temp_dir, '_ida_idaapi.pyd')
    if os.path.exists(idaapi_pyd):
        print(f"\n_ida_idaapi.pyd exists at: {idaapi_pyd}")
        print(f"Size: {os.path.getsize(idaapi_pyd)} bytes")
        try:
            # Try to load it directly
            ctypes.CDLL(idaapi_pyd)
            print("Successfully loaded _ida_idaapi.pyd")
        except Exception as e:
            print(f"Error loading _ida_idaapi.pyd: {str(e)}")
            print("\nDetailed error information:")
            traceback.print_exc()
    else:
        print("\n_ida_idaapi.pyd not found") 