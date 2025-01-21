import sys, os, platform

print("Python version:", sys.version)
print("Platform architecture:", platform.architecture()[0])
print("\nPython path:")
for p in sys.path:
    print(p)

print("\nTrying to import IDA modules...")
try:
    import ctypes
    print("\nLoading dependencies...")
    os.environ["PATH"] = os.environ.get("TEMP_MODULES_DIR", "") + os.pathsep + os.environ.get("PATH", "")
    ctypes.CDLL("ida.dll")
    print("Successfully loaded ida.dll")
except Exception as e:
    print("Error loading ida.dll:", str(e))

try:
    import ida_idaapi
    print("\nSuccessfully imported ida_idaapi")
    print("Module location:", ida_idaapi.__file__)
except ImportError as e:
    print("\nImport error:", str(e))
    print("Found .pyd files:", [f for f in os.listdir(".") if f.endswith(".pyd")]) 