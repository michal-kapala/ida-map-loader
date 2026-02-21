import idaapi, ida_kernwin, ida_name

FLAGS = ["t", "d", "b", "r", "f", "i", "c", "?"]
"""All MSVC symbol flags in MAP files."""

FUNCTION_FLAGS = ["t", "f"]
"""Function symbol flags in MSVC MAP files."""

class Symbol:
  # def __init__(self, values: list[str]):
  def __init__(self, values):
    address, name, offset, flags, lib_obj = self.parse_symbol(values)
    # segment_id:relative_offset
    self.address = address
    # msvc mangled name
    self.name = name
    # absolute offset
    self.offset = offset
    # t, d, b, r, f, i, c, ? (lowercase)
    self.flags = flags
    # library:object or module name
    self.lib_obj = lib_obj

  
  def __str__(self):
    type = ""
    if len(self.flags) > 0:
      for flag in self.flags:
        type += flag
      type += ": "
    return type + self.name + " @ " + hex(self.offset)

  # def parse_symbol(self, values: list[str]) -> tuple[str, str, int, list[str], str]
  def parse_symbol(self, values):
    address = values[0]
    name = values[1]
    offset = int(values[2], 16)
    flags = []
    # no flags, no module name with spaces
    if len(values) == 4:
      lib_obj = values[3]
      return address, name, offset, flags, lib_obj
    
    # check for flags
    idx = 3
    while str(values[idx]).lower() in FLAGS:
      flags.append(str(values[idx]).lower())
      idx += 1
    
    # check for module name with spaces (e.g. * CIL library *:* CIL module *)
    if idx >= len(values):
      err = "Symbol parsing error - no Lib:Object value"
      ida_kernwin.msg("[MAP Loader][ERROR] " + err + "\n")
      raise Exception(err)
    
    lib_obj = values[idx]
    # no spaces in Lib:Object
    if idx == len(values) - 1:
      return address, name, offset, flags, lib_obj
    
    # spaces in Lib:Object
    idx += 1
    while(idx < len(values)):
      lib_obj += values[idx]
      idx += 1

    return address, name, offset, flags, lib_obj


class MapFile:
  # def __init__(self, lines: list[str]):
  def __init__(self, lines):
    self.lines = lines
    self.name = self.read_name()
    self.time_info = self.read_time_info()
    self.load_addr_info = self.read_load_addr()
    self.segments = self.read_segments()
    # dynamic and static
    self.symbols = self.read_symbols()

  # def read_name(self) -> str:
  def read_name(self):
    return self.lines[0]
  
  # def read_time_info(self) -> str:
  def read_time_info(self):
    return self.lines[2]

  # def read_load_addr(self) -> str:
  def read_load_addr(self):
    return self.lines[4]

  # def read_segments(self) -> list[str]:
  def read_segments(self):
    columns = self.lines[6]
    start_idx = columns.find("Start")
    len_idx = columns.find("Length")
    name_idx = columns.find("Name")
    class_idx = columns.find("Class")
    segments = []
    if start_idx >= 0 and len_idx > 0 and name_idx > 0 and class_idx > 0:
      idx = 7
      line = self.lines[idx]
      while len(line) > 0:
        segments.append(line)
        idx += 1
        line = self.lines[idx]
      return segments
    else:
      ida_kernwin.msg("[MAP Loader][ERROR] Did not find segment list columns")
    return []
  
  # def read_symbols(self) -> list[Symbol]:
  def read_symbols(self):
    symbols = []
    # dynamic symbols
    columns = ["Address", "Publics by Value", "Rva+Base", "Lib:Object"]
    cols_idx = next((i for i, s in enumerate(self.lines) if all(col in s for col in columns)), -1)
    if cols_idx == -1:
      ida_kernwin.msg("[MAP Loader][ERROR] Did not find symbol list columns")
      return symbols
    
    # 1-line break
    idx = cols_idx + 2
    line = self.lines[idx]
    while len(line) > 0:
      values = [token for token in line.split(" ") if token is not ""]
      symbols.append(Symbol(values))
      idx += 1
      line = self.lines[idx]

    # static symbols
    cols_idx = next((i for i, s in enumerate(self.lines) if s == "Static symbols"), -1)
    if cols_idx == -1:
      ida_kernwin.msg("[MAP Loader][ERROR] Did not find static symbol list delimiter")
      return symbols
    
    # 1-line break
    idx = cols_idx + 2
    line = self.lines[idx]
    while len(line) > 0:
      values = [token for token in line.split(" ") if token is not ""]
      symbols.append(Symbol(values))
      idx += 1
      if idx == len(self.lines):
        break
      line = self.lines[idx]

    return symbols

# def read_map(path: str) -> list[Symbol]:
def read_map(path):
  lines = []
  with open(path) as file:
    lines = file.readlines()
  # remove useless whitespace
  for i, l in enumerate(lines):
    lines[i] = l[1:].replace("\r", "").replace("\n", "")
  map = MapFile(lines)
  return map

# def rename_functions(symbols: list[Symbol]) -> tuple[int, int]:
def rename_functions(symbols):
  renamed = 0
  func_symbols = [s for s in symbols if any(f in FUNCTION_FLAGS for f in s.flags)]
  for symbol in func_symbols:
    if ida_name.set_name(symbol.offset, symbol.name, ida_name.SN_FORCE):
      renamed += 1
  return renamed, len(func_symbols)

# def rename_data(symbols: list[Symbol]) -> tuple[int, int]:
def rename_data(symbols):
  renamed = 0
  data_symbols = [s for s in symbols if len(s.flags) == 0 and s.offset > 0]
  for symbol in data_symbols:
    if ida_name.set_name(symbol.offset, symbol.name, ida_name.SN_FORCE):
      renamed += 1
  return renamed, len(data_symbols)

def load_symbols():
  file_path = ida_kernwin.ask_file(False, "*.map", "Select MAP file")
  if file_path:
    ida_kernwin.msg("[MAP Loader][INFO] File: %s\n" % file_path)
  else:
    ida_kernwin.msg("[MAP Loader][ERROR] No file selected\n")
    return
  map = read_map(file_path)
  renamed, func_count = rename_functions(map.symbols)
  ida_kernwin.msg("[MAP Loader][INFO] Renamed: " + str(renamed) + "/" + str(func_count) + " functions\n")
  renamed, func_count = rename_data(map.symbols)
  ida_kernwin.msg("[MAP Loader][INFO] Renamed: " + str(renamed) + "/" + str(func_count) + " data offsets\n")

class FuncExporterPlugin(idaapi.plugin_t):
  flags = idaapi.PLUGIN_PROC
  comment = "IDA 7 MAP loader"
  help = "This plugin imports function symbols from MSVC .map files into IDB."
  wanted_name = "MAP loader"
  wanted_hotkey = "Shift+M"

  def init(self):
    return idaapi.PLUGIN_KEEP

  def term(self):
    pass

  def run(self, arg):
    load_symbols()

def PLUGIN_ENTRY():
  return FuncExporterPlugin()
