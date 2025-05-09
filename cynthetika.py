import socket
import subprocess
import sys
import os
import tempfile
import time
import shlex

SERVER_CODE = """
import sys
import inspect
from tree_format import format_tree
import socket
import threading
import marshal
from dis import dis
from types import ModuleType
import importlib._bootstrap_external

__cynthetika_server__ = True

class __CyNode:
    __cynthetika__ = True
    
    def __init__(self, name, children=None):
        self.name = name
        self.children = children or []

    def get_children(self):
        return self.children

def __cy_load_module_contents():
    module_globals = globals()
    current_module_name = __name__
    
    def is_server_item(obj):
        return (hasattr(obj, '__cynthetika__') or \
               any(name.startswith('__cy') for name in getattr(obj, '__qualname__', '').split('.')))
    
    return {
        'classes': {name: obj for name, obj in module_globals.items()
                   if inspect.isclass(obj) 
                   and obj.__module__ == current_module_name
                   and not is_server_item(obj)},
        
        'functions': {name: obj for name, obj in module_globals.items()
                     if inspect.isfunction(obj)
                     and obj.__module__ == current_module_name
                     and not is_server_item(obj)},
        
        'variables': {name: obj for name, obj in module_globals.items()
                     if not name.startswith('__cy')
                     and not name.startswith('__cynthetika')
                     and not inspect.isclass(obj)
                     and not inspect.isfunction(obj)
                     and not is_server_item(obj)}
    }

def __cy_handle_client(conn):
    with conn:
        data = conn.recv(1024).decode()
        parts = data.split(':', 1)
        if len(parts) != 2:
            return
        cmd, payload = parts
        
        output = ''
        try:
            if cmd == 'dump':
                obj = eval(payload)
                code_obj = obj.__code__
                pyc_header = importlib._bootstrap_external._code_to_timestamp_pyc(code_obj)
                with open(f"{payload}.pyc", "wb") as f:
                    f.write(pyc_header)
                    f.write(marshal.dumps(code_obj))
                output = f"Bytecode dumped to {payload}.pyc"
            
            elif cmd == 'dis':
                obj = eval(payload)
                code_obj = obj.__code__ if inspect.ismethod(obj) or inspect.isfunction(obj) else None
                if code_obj:
                    import io
                    buf = io.StringIO()
                    sys.stdout = buf
                    dis(code_obj)
                    sys.stdout = sys.__stdout__
                    output = buf.getvalue()
            
            elif cmd == 'structure':
                contents = __cy_load_module_contents()
                root = __CyNode("Module")
                for cls_name, cls in contents['classes'].items():
                    class_node = __CyNode(cls_name)
                    for name, _ in inspect.getmembers(cls, inspect.isfunction):
                        class_node.children.append(__CyNode(name))
                    root.children.append(class_node)
                for func_name in contents['functions']:
                    root.children.append(__CyNode(func_name))
                for var_name in contents['variables']:
                    root.children.append(__CyNode(f"{var_name} (variable)"))
                output = format_tree(root, lambda x: x.name, lambda x: x.get_children())
            
            elif cmd == 'getvar':
                contents = __cy_load_module_contents()
                var_value = contents['variables'].get(payload)
                if var_value is not None:
                    output = f"{payload}:\\n  Type: {type(var_value).__name__}\\n  Value: {repr(var_value)}"
                else:
                    output = f"Variable '{payload}' not found"
            
            elif cmd == 'exec':
                exec(payload, globals())
                output = "Code executed successfully"
            
            elif cmd == 'typevars':
                contents = __cy_load_module_contents()
                var_type = payload
                target_type = getattr(__builtins__, var_type, None)
                if not target_type:
                    output = f"Error: Type '{var_type}' is not a valid built-in type."
                else:
                    found = False
                    output_lines = [f"Variables of type {var_type} in module:"]
                    for var_name, var_value in contents['variables'].items():
                        if isinstance(var_value, target_type):
                            output_lines.append(f"{var_name}:")
                            output_lines.append(f"  Type: {type(var_value).__name__}")
                            output_lines.append(f"  Value: {repr(var_value)}")
                            found = True
                    if not found:
                        output_lines.append(f"No variables of type {var_type} found.")
                    output = "\\n".join(output_lines)
            
            elif cmd == 'searchattr':
                if "." not in payload:
                    output = "Invalid format. Use 'ClassName.attribute'"
                else:
                    cls_name, attr = payload.split(".", 1)
                    contents = __cy_load_module_contents()
                    cls = contents['classes'].get(cls_name)
                    if not cls:
                        output = f"Class '{cls_name}' not found"
                    else:
                        try:
                            instance = cls()
                            attr_value = getattr(instance, attr, 'Not found')
                            output = f"Attributes of {cls_name}:\\nInstance __dict__: {instance.__dict__}\\nAttribute value: {attr_value}"
                        except Exception as e:
                            output = f"Inspection error: {e}"
            
        except Exception as e:
            output = f"Error: {str(e)}"
        
        conn.sendall(output.encode())

def __cy_start_server():
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('localhost', 2804))
        s.listen()
        while True:
            conn, _ = s.accept()
            threading.Thread(target=__cy_handle_client, args=(conn,), name="__cynthetika_client_thread").start()

__cy_server_thread = threading.Thread(
    target=__cy_start_server,
    name="__cynthetika_server",
    daemon=True
)
__cy_server_thread.start()
"""

help_text = {
    "objects": "Display module structure. Usage: 'objects'",
    "dump": "Dump object bytecode. Usage: 'dump <object>'",
    "dis": "Disassemble object. Usage: 'dis <function>'",
    "get": "Get variable. Usage: 'get <variable>'",
    "typevars": "Find vars by type. Usage: 'typevars <type>'",
    "search": "Inspect class attributes. Usage: 'search <Class.attr>'",
    "rrun": "Execute code. Usage: 'rrun <file.py>'",
    "help": "Show help",
    "exit": "Exit debugger",
}

HELPER = "\n".join([f"{cmd}: {desc}" for cmd, desc in help_text.items()])

def inject_server(pid, verbose=False, gdb_prefix=""):
    """Executes a file in a running Python process."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".py") as f:
        f.write(SERVER_CODE)
    filename = os.path.abspath(f.name)
    gdb_cmds = [
        "PyGILState_Ensure()",
        'PyRun_SimpleString("'
        'import sys; sys.path.insert(0, \\"%s\\"); '
        'sys.path.insert(0, \\"%s\\"); '
        'exec(open(\\"%s\\").read())")'
        % (
            os.path.dirname(filename),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
            filename,
        ),
        "PyGILState_Release($1)",
    ]
    p = subprocess.Popen(
        "%sgdb -p %d -batch %s"
        % (
            gdb_prefix,
            pid,
            " ".join(["-eval-command='call (void*) %s'" % cmd for cmd in gdb_cmds]),
        ),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, err = p.communicate()
    if verbose:
        print(out.decode())
        print(err.decode())

def check_port():
    """Check if server is running"""
    try:
        with socket.socket() as s:
            s.settimeout(1)
            s.connect(('localhost', 2804))
            return True
    except:
        return False

def send_command(cmd, payload=""):
    """Send command to debug server"""
    try:
        with socket.socket() as s:
            s.settimeout(3)
            s.connect(('localhost', 2804))
            s.sendall(f"{cmd}:{payload}".encode())
            return s.recv(4096).decode()
    except Exception as e:
        return f"Connection error: {str(e)}"

def scan_python_processes():
    """Scan for Python processes and display PID and filename."""
    print("Scanning for Python processes...")
    current_pid = str(os.getpid())
    found = False

    try:
        ps_cmd = ["ps", "-ef"]
        result = subprocess.run(ps_cmd, capture_output=True, text=True, check=True)
        lines = result.stdout.splitlines()
        header = "{:<10} {}".format("PID", "Filename")
        print(header)
        print("-" * len(header))
        for line in lines[1:]:
            if "grep python" in line:
                continue
            parts = line.split(None, 7)
            if len(parts) < 8:
                continue
            pid = parts[1]
            if pid == current_pid:
                continue
            cmdline = parts[7]

            if "python" not in cmdline.lower() and ".py" not in cmdline.lower():
                continue

            try:
                args = shlex.split(cmdline)
                filename = None
                for arg in args:
                    if arg.lower().endswith(".py"):
                        filename = os.path.basename(arg)
                        break
                if filename:
                    print("{:<10} {}".format(pid, filename))
                    found = True
            except:
                continue

        if not found:
            print("No Python processes found.")
        print("-" * len(header))
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        if os.name == "posix":
            print("Try running 'ps -ef | grep python' manually.")
        else:
            print("Try running 'tasklist | findstr python' manually.")
    except Exception as e:
        print(f"Unexpected error: {e}")

def dbg_loop(pid):
    """Main debugger loop"""
    if not check_port():
        print("Injecting server...")
        inject_server(pid)
        time.sleep(2)
        
        if not check_port():
            print("Failed to start debug server")
            return

    print(f"Connected to process {pid}. Type 'help' for commands")
    
    while True:
        try:
            user_input = input("cynthetika-dbg> ").strip().split()
            if not user_input:
                continue
                
            cmd = user_input[0].lower()
            args = ' '.join(user_input[1:])
            
            if cmd == 'exit':
                break
                
            if cmd == 'help':
                print(HELPER)
                continue
                
            handlers = {
                'objects': ('structure', ''),
                'dump': ('dump', args),
                'dis': ('dis', args),
                'get': ('getvar', args),
                'typevars': ('typevars', args),
                'search': ('searchattr', args),
                'rrun': ('exec', f'exec(open("{args}").read())' if args.endswith('.py') else args)
            }
            
            if cmd not in handlers:
                print(f"Unknown command: {cmd}")
                continue
                
            server_cmd, payload = handlers[cmd]
            response = send_command(server_cmd, payload)
            print(response)
            
        except KeyboardInterrupt:
            print("\nUse 'exit' to quit")
        except Exception as e:
            print(f"Error: {str(e)}")

def main():
    """main function"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  dbg.py -scan  # Scan processes")
        print("  dbg.py <PID>  # Attach to process")
        return
        
    if sys.argv[1] == '-scan':
        scan_python_processes()
    elif sys.argv[1] == '-dbg':
        try:
            pid = int(sys.argv[2])
            dbg_loop(pid)
        except ValueError:
            print("Invalid PID")

if __name__ == '__main__':
    main()
