

function print_c_stack(context, str_tag) {
    console.log("=============================" + str_tag + " Stack strat=======================");
    console.log(Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n'));
    console.log("=============================" + str_tag + " Stack end  =======================");
}

function get_func_addr(module, offset, offsetx) {
    var base_addr = Module.findBaseAddress(module);
    if (Process.arch == 'arm') {
        console.log("model:arm");
        console.log("base_addr:", base_addr);
        var addr = base_addr.add(offset).add(1);
        // console.log("base_addr: " + base_addr);
        // console.log(hexdump(ptr(addr), {
        //     length: 16,
        //     header: true,
        //     ansi: false
        // }));
        return addr;
    }
    else {
        console.log("model:arm64");
        var addr = base_addr.add(offsetx);
        // console.log("base_addr: " + base_addr);
        // console.log(hexdump(ptr(addr), {
        //     length: 16,
        //     header: true,
        //     ansi: false
        // }));
        return addr;
    }
}



function inline_hook() {
    var crypto_addr = get_func_addr('libsscronet.so', 0x1CE804, 0x1CE804);
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






function main() {
    // hook_dlopen();
    recv('payload', print("大shapi:%s"))

}


setImmediate(main);