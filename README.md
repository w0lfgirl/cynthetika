# Cynthetika-dbg - Advanced Debugger for Obfuscated Python Scripts

**Cynthetika-dbg** is a powerful debugging tool designed to analyze and reverse-engineer obfuscated Python scripts. It provides an interactive shell to inspect running Python processes, dump bytecode, disassemble functions, retrieve variables, and inject code dynamically. Ideal for reverse engineering and security research.

---

## Features

- **Process Inspection**:  
  - Scan for running Python processes (`-scan`).  
  - Attach to a process by PID (`-dbg <PID>`).  

- **Interactive Commands**:  
  - `objects`: Display classes, functions, and variables in the target module.  
  - `dump <object>`: Dump an object's bytecode to a `.pyc` file.  
  - `dis <object>`: Disassemble an object's bytecode.  
  - `get <variable>`: Retrieve a variable's value and type.  
  - `get-all`: List all variables in the current scope.  
  - `search <class.attribute>`: Inspect class instance attributes.  
  - `rrun <code>`: Inject and execute arbitrary code in the target process.  
  - `help`: Show command help.  
  - `exit`: Quit the debugger.  

- **Code Injection**:  
  Dynamically execute code in the target process for runtime analysis.

---

## Requirements

- Python 3.6+
- `gdb` (GNU Debugger)
- Linux/macOS (not tested on Windows)
- `tree-format` library:  
  ```bash
  pip install tree-format
  ```

---

## Installation

```bash
git clone https://github.com/yourusername/cynthetika-dbg.git
cd cynthetika-dbg
```

---

## Usage

### 1. Scan for Python Processes
```bash
python cynthetika_dbg.py -scan
```
Example output:
```
PID        Filename
-------------------
1234       malware.py
5678       server.py
```

### 2. Attach to a Process
```bash
python cynthetika_dbg.py -dbg 1234
```
You’ll enter an interactive shell:
```
cynthetika-dbg > 
```

### 3. Example Commands

- **List all objects in the module**:
  ```
  cynthetika-dbg > objects
  ```

- **Dump bytecode of a function**:
  ```
  cynthetika-dbg > dump MyClass.secret_method
  # Output: MyClass.secret_method.pyc
  ```

- **Disassemble a function**:
  ```
  cynthetika-dbg > dis MyClass.__init__
  ```

- **Retrieve a variable**:
  ```
  cynthetika-dbg > get API_KEY
  ```

- **Inject code**:
  ```
  cynthetika-dbg > rrun 'print("Injected!")'
  ```

---

## Limitations

- Requires `gdb` and appropriate permissions to attach to processes.  
- Limited to CPython (tested on 3.6–3.10).  
- Bytecode dumping may fail for heavily obfuscated code.  

---
