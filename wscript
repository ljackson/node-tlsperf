

def set_options(opt):
  opt.tool_options("compiler_cxx")
  opt.tool_options("compiler_cc")

def configure(conf):
  conf.check_tool("compiler_cxx")
  conf.check_tool("compiler_cc")
  conf.check_tool("node_addon")

def build(bld):
  obj = bld.new_task_gen("cxx", "shlib", "node_addon")
  obj.cflags = ["-fPIC", "-I../deps/","-I/opt/local/include", "-std=c99","-fno-strict-aliasing", "-D_GNU_SOURCE", "-g", "-Wall"]
  obj.cxxflags = ["-g", "-D_GNU_SOURCE", "-D_FILE_OFFSET_BITS=64", "-D_LARGEFILE_SOURCE", "-Wall"]
  obj.target = "tlsperf"
  obj.env.append_value('LINKFLAGS', '-lcrypto -lssl'.split()) 
  obj.source = """
    src/tlsperf.cc
    src/connection.cc
    src/server.cc
    src/util.cc
  """
