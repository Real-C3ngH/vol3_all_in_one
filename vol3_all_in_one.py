import subprocess
import random
import sys
import re
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

VOL3_PLUGINS_PATH = "/Users/c3ngh/Tools/volatility3/volatility3/plugins"
VOL3_PATH = "/Users/c3ngh/Tools/volatility3/vol.py"

def random_emoji():

    return random.choice(['🎉', '🚀', '🚩', '💥', '🔥', '💭', '🎯', '🤗', '💖'])

def run_vol3_command(key, value, image_path, dir_path):
    print(f"{random_emoji()} 当前进行的任务为: {key}")

    out_file = os.path.join(dir_path, f"{value}.txt")
    cmd = [
        "python3",
        VOL3_PATH,
        "-p", VOL3_PLUGINS_PATH,
        "-f", image_path,
        value
    ]

    try:
        with open(out_file, "w", encoding="utf-8", errors="ignore") as f:
            subprocess.run(
                cmd,
                stdout=f,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
        print(f"✅ vol3: {key} 已执行完成")

    except Exception as e:
        print(f"😭 vol3: {key} 任务执行出现了一点问题, Error: {e}")

def vol3_confirm_profile():

    try:
        cmd = f'python3 {VOL3_PATH} -f {image_path} windows.info'
        out = subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )

        nt_major = re.search(r"NtMajorVersion\s+(\d+)", out)
        nt_minor = re.search(r"NtMinorVersion\s+(\d+)", out)
        is_64 = re.search(r"Is64Bit\s+(True|False)", out)
        build_lab = re.search(r"NTBuildLab\s+(.+)", out)
        system_root = re.search(r"NtSystemRoot\s+(.+)", out)

        if nt_major and nt_minor:
            major = int(nt_major.group(1))
            minor = int(nt_minor.group(1))
            arch = "x64" if is_64 and is_64.group(1) == "True" else "x86"
            version_str = f"{major}.{minor}"

            win_name_map = {
                (5, 1): "Windows XP",
                (5, 2): "Windows Server 2003",
                (6, 0): "Windows Vista / Server 2008",
                (6, 1): "Windows 7 / Server 2008 R2",
                (6, 2): "Windows 8 / Server 2012",
                (6, 3): "Windows 8.1 / Server 2012 R2",
                (10, 0): "Windows 10 / 11 / Server 2016+",
            }
            pretty_name = win_name_map.get((major, minor), f"Windows {version_str}")

            pretty = f"{pretty_name} {arch}"
            if build_lab:
                pretty += f" [{build_lab.group(1).strip()}]"
            if system_root:
                pretty += f" @ {system_root.group(1).strip()}"

            print(f"🌟 该内存镜像检测为：{pretty}")
            return "windows"

    except subprocess.CalledProcessError:
        pass

    try:
        cmd = f'python3 {VOL3_PATH} -f {image_path} banners.Banners'
        out = subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )

        m_linux = re.search(r"Linux version\s+(.+)", out)
        if m_linux:
            banner = m_linux.group(1).strip()
            print(f"🌟 该内存镜像检测为：Linux\n   ➜ 内核 banner: {banner}")
            return "linux"

        m_darwin = re.search(r"Darwin Kernel Version\s+([^\s]+)", out)
        if m_darwin:
            darwin_ver = m_darwin.group(1)
            print(f"🌟 该内存镜像检测为：macOS (Darwin Kernel {darwin_ver})")
            return "mac"

    except subprocess.CalledProcessError:
        pass

    try:
        strings_cmd = f"strings {image_path}"
        strings_out = subprocess.check_output(
            strings_cmd,
            shell=True,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            errors="ignore"
        )

        m_linux = re.search(r"Linux version\s+(.+)", strings_out)
        if m_linux:
            banner = m_linux.group(1).strip()
            print(f"🌟 该内存镜像通过strings可能识别为 Linux\n   ➜ 内核 banner: {banner}")
            return "linux"

        m_darwin = re.search(r"Darwin Kernel Version\s+([^\s]+)", strings_out)
        if m_darwin:
            print(f"🌟 该内存镜像通过strings可能识别为 macOS (Darwin Kernel {m_darwin.group(1)})")
            return "mac"


        if re.search(r"NtSystemRoot\\?\\Windows", strings_out, re.IGNORECASE):
            print("🌟 该内存镜像通过strings可能识别为 Windows")
            return "windows"

    except subprocess.CalledProcessError:
        pass

    # 全部失败
    print("😢 无法可靠识别系统类型，请检查符号表或手工确认一次～")
    return None


windows_plugins = {
    "列出所有进程": "windows.pslist.PsList",
    "扫描进程": "windows.psscan.PsScan",
    "进程树视图": "windows.pstree.PsTree",
    "隐藏进程检测": "windows.psxview.PsXView",
    "命令行历史": "windows.cmdline.CmdLine",
    "命令行扫描": "windows.cmdscan.CmdScan",
    "控制台会话": "windows.consoles.Consoles",
    "进程句柄": "windows.handles.Handles",
    "模块列表": "windows.modules.Modules",
    "内存模块扫描": "windows.modscan.ModScan",
    "驱动模块列表": "windows.drivermodule.DriverModule",
    "驱动模块扫描": "windows.driverscan.DriverScan",
    "加载的DLL": "windows.dlllist.DllList",
    "加载的LDR 模块": "windows.ldrmodules.LdrModules",
    "内存映射": "windows.memmap.Memmap",
    "物理内存池扫描": "windows.poolscanner.PoolScanner",
    "获取系统信息": "windows.info.Info",
    "进程环境变量": "windows.envars.Envars",
    "文件扫描": "windows.filescan.FileScan",
    "调试寄存器": "windows.debugregisters.DebugRegisters",
    "设备树": "windows.devicetree.DeviceTree",
    "内核回调函数": "windows.callbacks.Callbacks",
    "系统调试 SSDT": "windows.ssdt.SSDT",
    "会话管理": "windows.sessions.Sessions",
    "定时器": "windows.timers.Timers",
    "定时任务": "windows.scheduled_tasks.ScheduledTasks",
    "注册表密钥列表": "windows.registry.hivelist.HiveList",
    "注册表密钥扫描": "windows.registry.hivescan.HiveScan",
    "注册表键值解析": "windows.registry.printkey.PrintKey",
    "注册表用户辅助数据": "windows.registry.userassist.UserAssist",
    "注册表证书": "windows.registry.certificates.Certificates",
    "注册表GetCell解析": "windows.registry.getcellroutine.GetCellRoutine",
    "获取服务SID": "windows.getservicesids.GetServiceSIDs",
    "获取进程SID": "windows.getsids.GetSIDs",
    "权限信息": "windows.privileges.Privs",
    "进程钩取检测": "windows.unhooked_system_calls.unhooked_system_calls",
    "孤立的内核线程": "windows.orphan_kernel_threads.Threads",
    "线程列表": "windows.threads.Threads",
    "线程扫描": "windows.thrdscan.ThrdScan",
    "可执行文件转储": "windows.pedump.PEDump",
    "PE符号解析": "windows.pe_symbols.PESymbols",
    "哈希提取": "windows.hashdump.Hashdump",
    "LSASS密码转储": "windows.lsadump.Lsadump",
    "Amcache取证": "windows.amcache.Amcache",
    "Shimcache取证": "windows.shimcachemem.ShimcacheMem",
    "驱动IRP处理": "windows.driverirp.DriverIrp",
    "系统MBR扫描": "windows.mbrscan.MBRScan",
    "进程劫持检测": "windows.processghosting.ProcessGhosting",
    "Hollow进程检测": "windows.hollowprocesses.HollowProcesses",
    "可疑线程检测": "windows.suspicious_threads.SuspiciousThreads",
    "未加载的模块": "windows.unloadedmodules.UnloadedModules",
    "虚拟地址信息": "windows.vadinfo.VadInfo",
    "虚拟地址遍历": "windows.vadwalk.VadWalk",
    "网络连接扫描": "windows.netscan.NetScan",
    "NetStat网络状态": "windows.netstat.NetStat",
    "服务列表": "windows.svclist.SvcList",
    "服务扫描": "windows.svcscan.SvcScan",
    "服务对比差异": "windows.svcdiff.SvcDiff",
    "符号链接扫描": "windows.symlinkscan.SymlinkScan",
    "可执行文件 IAT 分析": "windows.iat.IAT",
    "统计信息": "windows.statistics.Statistics",
    "字符串提取": "windows.strings.Strings",
    "Job任务链接": "windows.joblinks.JobLinks",
    "KPCR结构": "windows.kpcrs.KPCRs",
    "内核突变扫描": "windows.mutantscan.MutantScan",
    "TrueCrypt密码解析": "windows.truecrypt.Passphrase",
    "崩溃信息": "windows.crashinfo.Crashinfo",
    "权限提升检测": "windows.skeleton_key_check.Skeleton_Key_Check",
    "进程VAD映射": "windows.virtmap.VirtMap",
    #"驱动文件转储": "windows.dumpfiles.DumpFiles", 这个会在同目录下生成一大堆文件，所以默认注释
    "系统版本信息": "windows.verinfo.VerInfo",
    "大块内存池分析": "windows.bigpools.BigPools",
    "提取凭据缓存": "windows.cachedump.Cachedump",
    "恶意代码检测": "windows.malfind.Malfind"
}

linux_plugins = {
    "系统横幅信息": "banners.Banners",
    "配置写入": "configwriter.ConfigWriter",
    "框架信息": "frameworkinfo.FrameworkInfo",
    "ISF 解析信息": "isfinfo.IsfInfo",
    "层写入": "layerwriter.LayerWriter",
    "Bash 历史": "linux.bash.Bash",
    "系统启动时间": "linux.boottime.Boottime",
    "进程能力列表": "linux.capabilities.Capabilities",
    "AF 网络信息": "linux.check_afinfo.Check_afinfo",
    "进程凭据检查": "linux.check_creds.Check_creds",
    "IDT 中断描述符表检查": "linux.check_idt.Check_idt",
    "加载的模块检查": "linux.check_modules.Check_modules",
    "系统调用检查": "linux.check_syscall.Check_syscall",
    "eBPF 过滤器": "linux.ebpf.EBPF",
    "ELF 可执行文件分析": "linux.elfs.Elfs",
    "环境变量": "linux.envars.Envars",
    "隐藏模块检测": "linux.hidden_modules.Hidden_modules",
    "I/O 内存映射": "linux.iomem.IOMem",
    "键盘监听进程": "linux.keyboard_notifiers.Keyboard_notifiers",
    "内核日志": "linux.kmsg.Kmsg",
    "内核线程列表": "linux.kthreads.Kthreads",
    "加载的库列表": "linux.library_list.LibraryList",
    "已加载的内核模块": "linux.lsmod.Lsmod",
    "打开的文件": "linux.lsof.Lsof",
    "恶意代码检测": "linux.malfind.Malfind",
    "挂载点信息": "linux.mountinfo.MountInfo",
    "Netfilter 防火墙规则": "linux.netfilter.Netfilter",
    "PageCache 缓存文件": "linux.pagecache.Files",
    "PageCache 缓存 Inode 映射": "linux.pagecache.InodePages",
    "PID 哈希表检查": "linux.pidhashtable.PIDHashTable",
    "进程内存映射": "linux.proc.Maps",
    "进程命令行信息": "linux.psaux.PsAux",
    "进程列表": "linux.pslist.PsList",
    "进程扫描": "linux.psscan.PsScan",
    "进程树": "linux.pstree.PsTree",
    "进程调试跟踪": "linux.ptrace.Ptrace",
    "套接字状态": "linux.sockstat.Sockstat",
    "TTY 终端检查": "linux.tty_check.tty_check"
}

mac_plugins = {
    "Bash 历史": "mac.bash.Bash",
    "系统调用检查": "mac.check_syscall.Check_syscall",
    "系统控制变量检查": "mac.check_sysctl.Check_sysctl",
    "中断向量表检查": "mac.check_trap_table.Check_trap_table",
    "内核消息日志": "mac.dmesg.Dmesg",
    "网络接口信息": "mac.ifconfig.Ifconfig",
    "内核认证监听器": "mac.kauth_listeners.Kauth_listeners",
    "内核认证作用域": "mac.kauth_scopes.Kauth_scopes",
    "内核事件监听": "mac.kevents.Kevents",
    "文件列表": "mac.list_files.List_Files",
    "已加载的内核模块": "mac.lsmod.Lsmod",
    "打开的文件": "mac.lsof.Lsof",
    "恶意代码检测": "mac.malfind.Malfind",
    "挂载点信息": "mac.mount.Mount",
    "网络连接状态": "mac.netstat.Netstat",
    "进程内存映射": "mac.proc_maps.Maps",
    "进程命令行信息": "mac.psaux.Psaux",
    "进程列表": "mac.pslist.PsList",
    "进程树": "mac.pstree.PsTree",
    "套接字过滤器": "mac.socket_filters.Socket_filters",
    "定时器信息": "mac.timers.Timers",
    "TrustedBSD 安全策略": "mac.trustedbsd.Trustedbsd",
    "文件系统事件": "mac.vfsevents.VFSevents"
}

try:
    image_path = sys.argv[1]
    image_name = image_path.split('/')[-1]

except IndexError:
    sys.exit("😢 请输入待分析的内存镜像的路径...")

dir_path = image_path.replace(image_name, "vol_output")
os.makedirs(dir_path, exist_ok=True)

if __name__ == "__main__":

    system = vol3_confirm_profile()

    if not system:
        sys.exit("😢 无法确定系统类型，退出分析...")

    print("✅ 已确认系统版本，自动开始分析...")

    plugins_to_use = {
        'windows': windows_plugins,
        'linux': linux_plugins,
        'mac': mac_plugins
    }.get(system)

    if not plugins_to_use:
        sys.exit("😢 未找到对应系统的插件配置，退出分析...")

    tasks = list(plugins_to_use.items())
    num_tasks = len(tasks)

    max_workers = min(os.cpu_count(), num_tasks)

    print(f"🔍 正在使用 {max_workers} 个并发任务分析，共 {num_tasks} 个插件...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_key = {
            executor.submit(run_vol3_command, key, value, image_path, dir_path): key
            for key, value in tasks
        }

        for future in as_completed(future_to_key):
            key = future_to_key[future]
            try:
                future.result()
            except Exception as e:
                print(f"🤕 插件 {key} 执行时抛出了未捕获异常: {e}")

    print(f"🎊 所有任务执行完成！结果保存在 {dir_path} 目录下")