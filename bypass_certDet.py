import frida
import sys
import click
from shutil import get_terminal_size as get_terminal_size
import random
from passplugin.find_vert import *
from idc_bc695 import *
#import pyperclip #剪贴板
import idautils
import idaapi
import idc




 

class CopyFunctionAsm(idaapi.plugin_t):
    comment = "Copy here Function assembly to clip" #插件描述
    help = "todo"                                   #帮助信息
    wanted_name = "DYCRTPass"              #菜单中显示的名字
    wanted_hotkey = "Ctrl-Alt-c"                    #希望注册的快捷键
    flags = 0                                       #插件的特征
 
    def __init__(self):
        super(CopyFunctionAsm,self).__init__()
        self._data = None
 
    def term(self):#相当于析构函数
        print("[+] copy func asm plugin term......")
 
    def init(self):#相当于构造函数
        self.view = None
        print("[+] copy func asm plugin init .....")
        return idaapi.PLUGIN_OK                    #任何情况我们都可以的
    
    
    
    def on_message(self,message, data):
        # global file_sskkey
        if message['type'] == 'send':
            # file_sskkey.write(message['payload'] + "\n")
            # file_sskkey.flush()
            print(message['payload'])
        else:
            pass
        # name = find_vert()
        script.post({'type': 'input', 'payload': str(2 * 2)})


    banner = """
    -----------------------------------------------------
     ____    ____    __      ____    ____    ____ 
    (  __)  (  _ \  (  )    (  __)  (  __)  (  __)
     ) _)    ) _ (  / |_/\   ) _)    ) _)    ) _) 
    (__)    (____/  \____/  (____)  (____)  (____)
                                                                                                                                                                            
    https://github.com/FBLeee/frida_bypass_certDet
    -----------------------------------------------------\n
    """


    def show_banner(self):
        colors = ['bright_red', 'bright_green', 'bright_blue', 'cyan', 'magenta']
        try:
            click.style('color test', fg='bright_red')
        except:
            colors = ['red', 'green', 'blue', 'cyan', 'magenta']
        try:
            columns = get_terminal_size().columns
            if columns >= len(banner.splitlines()[1]):
                for line in banner.splitlines():
                    click.secho(line, fg=random.choice(colors))
        except:
            pass


    
    
    
    def bypass_code(self):
        self.show_banner()

        pid = frida.get_usb_device().spawn(["com.ss.android.ugc.aweme"])
        process = frida.get_usb_device().attach(pid)
        # jscode = open("C:/Users/FH/Desktop/IDAp/self/pass/bypass_certDet.js",
        #               "r", encoding='UTF-8').read()

        str_find = find_vert()
        print("str_find:", str_find)
        jscode = """

        hook_dlopen();

        function get_func_addr(module, offset, offsetx) 
        {
            var base_addr = Module.findBaseAddress(module);
            if (Process.arch == 'arm') {
                console.log("model:arm");
                console.log("base_addr:", base_addr);
                var addr = base_addr.add(offset).add(1);
                return addr;
            }
            else {
                console.log("model:arm64");
                var addr = base_addr.add(offsetx);
                return addr;
            }
        }



        function inline_hook() {
            var crypto_addr = get_func_addr('libsscronet.so', %s, %s);
            Interceptor.attach(ptr(crypto_addr), {
                onEnter: function (args) {
                },
                onLeave: function (retval) {
                    console.log("------Bypass certificate detection------");
                    retval.replace(0);
                }
            });
        }





        function hook_dlopen() {
            //安卓6.0及以下用这个版本
            var dlopen = Module.findExportByName(null, "dlopen");
            Interceptor.attach(dlopen, {
                onEnter: function (args) {
                    this.call_hook = false;
                    var so_name = ptr(args[0]).readCString();
                    if (so_name.indexOf("libsscronet.so") >= 0) {
                        // console.log("dlopen:", ptr(args[0]).readCString());
                        this.call_hook = true;
                    }
                }, onLeave: function (retval) {
                    if (this.call_hook) {
                        inline_hook();
                    }
                }
            });
            // 6.0以上的高版本Android系统使用android_dlopen_ext
            var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
            Interceptor.attach(android_dlopen_ext, {
                onEnter: function (args) {
                    this.call_hook = false;
                    var so_name = ptr(args[0]).readCString();
                    if (so_name.indexOf("libsscronet.so") >= 0) {
                        // console.log("android_dlopen_ext:", ptr(args[0]).readCString());
                        this.call_hook = true;
                    }
                }, onLeave: function (retval) {
                    if (this.call_hook) {
                        inline_hook();
                    }
                }
            });
        }


        """ % (str_find, str_find)

        script = process.create_script(jscode)
        frida.get_usb_device().resume(pid)
        script.on('message', self.on_message)
        script.load()
        sys.stdin.read()
 
    def run(self,arg):
        self.bypass_code()
        







 
# register IDA plugin
def PLUGIN_ENTRY():
    return CopyFunctionAsm()