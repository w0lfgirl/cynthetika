import os
import shlex
import subprocess
import sys

help_text = {
    "objects": "Display the structure of objects in the process memory. Usage: 'objects'",
    "dump": "Dump the bytecode of a specified object. Usage: 'dump <object_name>'",
    "dis": "Disassemble the bytecode of a specified object. Usage: 'dis <object_name>'",
    "get": "Get the value of a specific variable. Usage: 'get <variable_name>'",
    "get-all": "Get all variables in the current scope. Usage: 'get-all'",
    "search": "Search for objects or variables in memory. Usage: 'search <query>'",
    "rrun": "Inject and run code in the target process. Usage: 'rrun <code>'",
    "help": "Display this help message. Usage: 'help'",
    "exit": "Exit the interactive shell. Usage: 'exit'",
}

HELPER = "\n".join([f"{cmd}: {desc}" for cmd, desc in help_text.items()])

LOAD_STRUCTURE_CODE = """
import inspect
import sys
from typing import Dict, List, Optional
from tree_format import format_tree


def load_module_contents() -> Dict[str, Dict]:
    module_globals = globals()
    current_module_name = __name__

    classes = {}
    functions = {}
    variables = {}

    for name, obj in module_globals.items():
        if name.startswith("__"):
            continue

        if inspect.isclass(obj):
            if getattr(obj, "__module__", None) == current_module_name:
                classes[name] = obj
        elif inspect.isfunction(obj):
            if (
                getattr(obj, "__module__", None) == current_module_name
                and obj.__qualname__ == name
            ):
                functions[name] = obj
        else:
            variables[name] = obj

    return {"classes": classes, "functions": functions, "variables": variables}


class Node:

    def __init__(self, name: str, children: Optional[List["Node"]] = None):
        self.name = name
        self.children = children or []

    def get_children(self) -> List["Node"]:
        return self.children"""


def inject(pid, filename, verbose=False, gdb_prefix=""):
    """Executes a file in a running Python process."""
    filename = os.path.abspath(filename)
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
        print(out)
        print(err)


def dump_bytecode(pid, item) -> None:
    """Dump bytecode for functions or methods."""
    try:
        code = f"""
import importlib._bootstrap_external, marshal
code_obj = {item}.__code__
pyc_header = importlib._bootstrap_external._code_to_timestamp_pyc(code_obj, 0)
with open("{item}.pyc", "wb") as f:
    f.write(pyc_header)
    f.write(marshal.dumps(code_obj))"""
        with open("_temp.py", "w", encoding="utf-8") as f:
            f.write(code)
        inject(pid, "_temp.py")
        os.remove("_temp.py")
    except Exception as e:
        print(f"Error dumping {item}: {e}")


def dis_bytecode(pid, item) -> None:
    """Dump bytecode for functions or methods."""
    try:
        code = f"""__import__('dis').dis({item}.__code__)"""
        with open("_temp.py", "w", encoding="utf-8") as f:
            f.write(code)
        inject(pid, "_temp.py")
        os.remove("_temp.py")
    except Exception as e:
        print(f"Error dumping {item}: {e}")


def inspect_class_attributes(pid, data) -> None:
    """Inspect attributes of a class instance."""
    try:
        code = """
def inspect_class_attributes(class_obj: type, attribute_name: str) -> None:
    try:
        instance = class_obj()
        print(f"Attributes of {class_obj.__name__}:")
        print("Instance __dict__:", instance.__dict__)
        print("Attribute value:", getattr(instance, attribute_name, "Not found"))
    except Exception as e:
        print(f"Inspection error: {e}")"""
        code2 = f"""
data = "{data}"
if "." in data:
    cls_name, attr = data.split(".", 1)
    cls = load_module_contents()["classes"].get(cls_name)
    if cls:
        inspect_class_attributes(cls, attr)"""
        with open("_temp.py", "w", encoding="utf-8") as f:
            f.write(LOAD_STRUCTURE_CODE + code + code2)
        inject(pid, "_temp.py")
        os.remove("_temp.py")
    except Exception as e:
        print(f"Inspection error: {e}")


def display_structure(pid) -> None:
    """Display module structure or specific class methods, including variables."""
    code = """
def display_structure(contents: Dict, class_name: str = None) -> None:
    root = Node("Module") if not class_name else Node(class_name)

    if class_name:
        cls = contents["classes"].get(class_name)
        if not cls:
            print("Class not found")
            return
        for name, _ in inspect.getmembers(cls, inspect.isfunction):
            root.children.append(Node(name))
    else:
        for cls_name, cls in contents["classes"].items():
            class_node = Node(cls_name)
            for name, _ in inspect.getmembers(cls, inspect.isfunction):
                class_node.children.append(Node(name))
            root.children.append(class_node)
        for func_name in contents["functions"]:
            root.children.append(Node(func_name))
        for var_name in contents["variables"]:
            root.children.append(Node(f"{var_name} (variable)"))

    print(format_tree(root, lambda x: x.name, lambda x: x.get_children()))


contents = load_module_contents()
display_structure(contents)
"""
    with open("_temp.py", "w", encoding="utf-8") as f:
        f.write(LOAD_STRUCTURE_CODE + code)
    inject(pid, "_temp.py")
    os.remove("_temp.py")


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


def get_variable(pid, var):
    """get variable by name"""
    code = f'\ncontents = load_module_contents()\nvar_name = "{var}"'
    code1 = """
var_value = contents["variables"].get(var_name)
if var_value is not None:
    print(f"{var_name}:")
    print(f"  Type: {type(var_value).__name__}")
    print(f"  Value: {repr(var_value)}")
else:
    print(f"Variable '{var_name}' not found in module")"""
    with open("_temp.py", "w", encoding="utf-8") as f:
        f.write(LOAD_STRUCTURE_CODE + code + code1)
    inject(pid, "_temp.py")
    os.remove("_temp.py")


def get_all_variables(pid, var_type):
    """get all variables by type"""
    code1 = """
variables = load_module_contents().get("variables", {})
if not variables:
    print("No variables found in module")
else:"""
    code2 = f"""
    type_name = "{var_type}"
"""
    code3 = """
    target_type = getattr(__builtins__, type_name, None)
    if not target_type:
        print(f"Error: Type '{type_name}' is not a valid built-in type.")
    else:
        found = False
        print(f"Variables of type {type_name} in module:")
        for var_name, var_value in variables.items():
            if isinstance(var_value, target_type):
                print(f"{var_name}:")
                print(f"  Type: {type(var_value).__name__}")
                print(f"  Value: {repr(var_value)}")
                found = True
        if not found:
            print(f"No variables of type {type_name} found.")"""
    with open("_temp.py", "w", encoding="utf-8") as f:
        f.write(LOAD_STRUCTURE_CODE + code1 + code2 + code3)
    inject(pid, "_temp.py")
    os.remove("_temp.py")


def dbg(pid):
    """debugger function"""
    while True:
        user_input = input("cynthetika-dbg > ").strip().split()
        command = user_input[0].lower()
        data = " ".join(user_input[1:]) if len(user_input) > 1 else ""
        functions = {
            "objects": lambda: display_structure(pid),
            "dump": lambda: dump_bytecode(pid, data),
            "dis": lambda: dis_bytecode(pid, data),
            "get": lambda: get_variable(pid, data),
            "objects-type": lambda: get_all_variables(pid, data),
            "search": lambda: inspect_class_attributes(pid, data),
            "rrun": lambda: inject(pid, data),
            "help": lambda: print(HELPER),
            "exit": exit,
        }
        if command in functions:
            functions[command]()


def main() -> None:
    """main function"""
    if sys.argv[1] == "-scan":
        scan_python_processes()
    elif sys.argv[1] == "-dbg":
        dbg(int(sys.argv[2]))


if __name__ == "__main__":
    main()
