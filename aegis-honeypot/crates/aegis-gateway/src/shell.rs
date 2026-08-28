//! Shell command dispatcher — zero-execution fake shell built on top of the VFS.
//! All recon commands return realistic static output matching the server profile.

use super::vfs::VirtualFileSystem;

const UNAME: &str = "Linux ubuntu-server-01 5.15.0-72-generic #79-Ubuntu SMP Wed Apr 19 08:22:18 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n";

const PS_AUX: &str = "\
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n\
root         1  0.0  0.1 165924  9080 ?        Ss   Aug26   0:03 /sbin/init\r\n\
root       512  0.0  0.1  72296  5584 ?        Ss   Aug26   0:00 /lib/systemd/systemd-journald\r\n\
root       783  0.0  0.0 104740  1736 ?        Ssl  Aug26   0:00 /usr/sbin/rsyslogd -n\r\n\
root       849  0.0  0.0  72292  2092 ?        Ss   Aug26   0:00 /usr/sbin/cron -f\r\n\
root      1200  0.0  0.1  71828  5912 ?        Ss   Aug26   0:00 /usr/sbin/sshd -D\r\n\
root      1822  0.0  0.1 107700  7228 ?        Ss   18:12   0:00 sshd: root@pts/0\r\n\
root      1824  0.0  0.0  21336  4488 pts/0    Ss   18:12   0:00 -bash\r\n\
www-data  2100  0.0  0.5 190120 21032 ?        S    Aug26   0:12 nginx: worker process\r\n\
root      2099  0.0  0.1  54876  4472 ?        Ss   Aug26   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;\r\n\
root      2901  0.0  0.3 1487420 13588 ?       Ssl  Aug26   0:15 dockerd --host=fd:// --containerd=/run/containerd/containerd.sock\r\n\
root      3100  0.0  0.2 711100 10644 ?        Ssl  Aug26   0:02 /usr/bin/containerd\r\n\
mysql     4122  0.1  3.2 1821196 132488 ?      Sl   Aug26   1:23 /usr/sbin/mysqld\r\n\
";

const NETSTAT: &str = "\
Active Internet connections (w/o servers)\r\n\
Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n\
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n\
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n\
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\r\n\
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\r\n\
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN\r\n\
tcp6       0      0 :::22                   :::*                    LISTEN\r\n\
tcp6       0      0 :::80                   :::*                    LISTEN\r\n\
";

const SS_OUT: &str = "\
Netid    State    Recv-Q  Send-Q    Local Address:Port     Peer Address:Port  Process\r\n\
tcp      LISTEN   0       128             0.0.0.0:22            0.0.0.0:*     users:((\"sshd\",pid=1200,fd=3))\r\n\
tcp      LISTEN   0       511             0.0.0.0:80            0.0.0.0:*     users:((\"nginx\",pid=2099,fd=6))\r\n\
tcp      LISTEN   0       511             0.0.0.0:443           0.0.0.0:*     users:((\"nginx\",pid=2099,fd=7))\r\n\
tcp      LISTEN   0       128           127.0.0.1:3306          0.0.0.0:*     users:((\"mysqld\",pid=4122,fd=29))\r\n\
";

const IFCONFIG: &str = "\
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n\
        inet 10.0.0.4  netmask 255.255.255.0  broadcast 10.0.0.255\r\n\
        inet6 fe80::215:5dff:fe00:1  prefixlen 64  scopeid 0x20<link>\r\n\
        ether 00:15:5d:00:00:01  txqueuelen 1000  (Ethernet)\r\n\
        RX packets 184293 bytes 217234891 (207.2 MiB)\r\n\
        TX packets 40237 bytes 5827433 (5.5 MiB)\r\n\
\r\n\
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n\
        inet 127.0.0.1  netmask 255.0.0.0\r\n\
        inet6 ::1  prefixlen 128  scopeid 0x10<host>\r\n\
        loop  txqueuelen 1000  (Local Loopback)\r\n\
";

const IP_A: &str = "\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\r\n\
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\r\n\
    inet 127.0.0.1/8 scope host lo\r\n\
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000\r\n\
    link/ether 00:15:5d:00:00:01 brd ff:ff:ff:ff:ff:ff\r\n\
    inet 10.0.0.4/24 brd 10.0.0.255 scope global eth0\r\n\
";

const LSCPU: &str = "\
Architecture:                    x86_64\r\n\
CPU op-mode(s):                  32-bit, 64-bit\r\n\
Byte Order:                      Little Endian\r\n\
Address sizes:                   46 bits physical, 48 bits virtual\r\n\
CPU(s):                          4\r\n\
On-line CPU(s) list:             0-3\r\n\
Thread(s) per core:              1\r\n\
Core(s) per socket:              4\r\n\
Socket(s):                       1\r\n\
Model name:                      Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\r\n\
CPU MHz:                         2400.062\r\n\
BogoMIPS:                        4800.12\r\n\
L3 cache:                        30720K\r\n\
NUMA node0 CPU(s):               0-3\r\n\
";

const CRONTAB_L: &str = "\
# Edit this file to introduce tasks to be run by cron.\r\n\
# m h  dom mon dow   command\r\n\
0 2 * * *  /bin/bash /root/backup.sh >> /var/log/backup.log 2>&1\r\n\
*/15 * * * *  curl -s http://monitoring.internal/health > /dev/null\r\n\
";

const ENV: &str = "\
HOME=/root\r\n\
SHELL=/bin/bash\r\n\
USER=root\r\n\
LOGNAME=root\r\n\
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\n\
LANG=en_US.UTF-8\r\n\
TERM=xterm-256color\r\n\
SHLVL=1\r\n\
_=/usr/bin/env\r\n\
";

const LAST: &str = "\
root     pts/0        192.168.1.100    Mon Aug 26 22:14   still logged in\r\n\
root     pts/0        185.220.101.45   Mon Aug 26 03:12 - 03:14  (00:01)\r\n\
root     pts/0        45.33.32.156     Sun Aug 25 19:44 - 19:47  (00:02)\r\n\
ubuntu   pts/1        192.168.1.100    Sat Aug 24 15:30 - 17:22  (01:52)\r\n\
\r\n\
wtmp begins Wed Aug 01 00:00:00 2026\r\n\
";

const DF_H: &str = "\
Filesystem      Size  Used Avail Use% Mounted on\r\n\
/dev/sda1        50G   18G   30G  38% /\r\n\
tmpfs           3.9G     0  3.9G   0% /dev/shm\r\n\
/dev/sda15      105M  5.3M  100M   6% /boot/efi\r\n\
";

const FREE_H: &str = "\
               total        used        free      shared  buff/cache   available\r\n\
Mem:           7.8Gi       2.1Gi       3.0Gi        74Mi       2.7Gi       5.4Gi\r\n\
Swap:          2.0Gi          0B       2.0Gi\r\n\
";

const UPTIME: &str = " 18:25:01 up 15 days,  6:12,  1 user,  load average: 0.12, 0.08, 0.03\r\n";

const W: &str = "\
 18:25:01 up 15 days,  6:12,  1 user,  load average: 0.12, 0.08, 0.03\r\n\
USER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT\r\n\
root     pts/0    192.168.1.100   18:12    0.00s  0.06s  0.01s -bash\r\n\
";

/// Dispatch a shell command and return the fake response string.
pub fn dispatch(cmd: &str, vfs: &mut VirtualFileSystem) -> String {
    let cmd = cmd.trim();

    // Handle redirections: cmd > file or cmd >> file
    if let Some((cmd_part, redir, file_part)) = parse_redirect(cmd) {
        let output = dispatch_pure(cmd_part.trim(), vfs);
        let append = redir == ">>";
        // Strip \r\n for file storage
        let content = output.replace("\r\n", "\n");
        vfs.write_file(file_part.trim(), &content, append);
        return String::new();
    }

    // Semicolon-separated commands
    if cmd.contains(';') {
        let parts: Vec<&str> = cmd.split(';').collect();
        return parts
            .iter()
            .map(|c| dispatch(c.trim(), vfs))
            .collect::<Vec<_>>()
            .join("");
    }

    dispatch_pure(cmd, vfs)
}

fn parse_redirect(cmd: &str) -> Option<(&str, &str, &str)> {
    if let Some(pos) = cmd.find(">>") {
        return Some((&cmd[..pos], ">>", &cmd[pos+2..]));
    }
    if let Some(pos) = cmd.rfind('>') {
        // Avoid matching >=
        if cmd.as_bytes().get(pos+1).copied() != Some(b'=') {
            return Some((&cmd[..pos], ">", &cmd[pos+1..]));
        }
    }
    None
}

fn dispatch_pure(cmd: &str, vfs: &mut VirtualFileSystem) -> String {
    if cmd.is_empty() { return String::new(); }

    let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
    let prog = parts[0];
    let args = parts.get(1).copied().unwrap_or("");

    // sudo passthrough — strip "sudo " and re-dispatch
    if prog == "sudo" {
        return dispatch_pure(args, vfs);
    }

    match prog {
        "pwd"       => vfs.pwd(),
        "cd"        => { let r = vfs.cd(args); if r.is_empty() { String::new() } else { r } }
        "ls"        => vfs.ls(args),
        "cat"       => vfs.cat(args),
        "mkdir"     => vfs.mkdir(args),
        "touch"     => vfs.touch(args),
        "rm"        => vfs.rm(args),
        "echo"      => {
            // Strip only surrounding matching quotes from the whole arg string
            let s = args.trim();
            let s = if (s.starts_with('"') && s.ends_with('"')) ||
                       (s.starts_with('\'') && s.ends_with('\'')) {
                &s[1..s.len()-1]
            } else {
                s
            };
            format!("{}\r\n", s)
        }
        "whoami"    => "root\r\n".into(),
        "id"        => "uid=0(root) gid=0(root) groups=0(root)\r\n".into(),
        "hostname"  => "ubuntu-server-01\r\n".into(),
        "uname"     => {
            if args.contains('a') { UNAME.into() }
            else if args.contains('r') { "5.15.0-72-generic\r\n".into() }
            else if args.contains('s') { "Linux\r\n".into() }
            else { "Linux\r\n".into() }
        }
        "ps"        => PS_AUX.into(),
        "netstat"   => NETSTAT.into(),
        "ss"        => SS_OUT.into(),
        "ifconfig"  => IFCONFIG.into(),
        "ip"        => {
            if args.starts_with('a') { IP_A.into() }
            else { IP_A.into() }
        }
        "lscpu"     => LSCPU.into(),
        "env" | "printenv" => ENV.into(),
        "crontab"   => {
            if args.contains('l') { CRONTAB_L.into() }
            else { String::new() }
        }
        "last"      => LAST.into(),
        "w"         => W.into(),
        "who"       => "root     pts/0        2026-08-26 22:14 (192.168.1.100)\r\n".into(),
        "uptime"    => UPTIME.into(),
        "df"        => DF_H.into(),
        "free"      => FREE_H.into(),
        "history"   => {
            let entries = ["apt-get update", "systemctl status nginx", "docker ps",
                           "cat /etc/hosts", "ufw status", "ls -la /root"];
            entries.iter().enumerate()
                .map(|(i, e)| format!("  {:<4}{}\r\n", i+1, e))
                .collect()
        }
        "clear"     => "\x1b[2J\x1b[H".into(),
        "python" | "python3" => {
            if args.is_empty() {
                "Python 3.10.6 (main, Nov 14 2022, 16:10:14) [GCC 11.3.0] on linux\r\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\r\n>>> ".into()
            } else {
                String::new()
            }
        }
        "which"     => {
            let known = ["bash","sh","python","python3","perl","curl","wget","tar","gzip",
                         "ls","cat","rm","mv","cp","mkdir","touch","find","grep","awk",
                         "sed","chmod","chown","systemctl","apt","apt-get"];
            let prog_name = args.trim().split_whitespace().next().unwrap_or("");
            if known.contains(&prog_name) {
                format!("/usr/bin/{prog_name}\r\n")
            } else {
                String::new()
            }
        }
        "chmod" | "chown" | "chattr" | "lsattr" => String::new(),
        "systemctl" => {
            if args.starts_with("status") {
                let svc = args.strip_prefix("status").unwrap_or("").trim();
                format!("● {svc}.service - {svc}\r\n   Loaded: loaded\r\n   Active: active (running)\r\n")
            } else {
                String::new()
            }
        }
        "service"   => String::new(),
        "apt" | "apt-get" => {
            "Reading package lists... Done\r\nBuilding dependency tree... Done\r\nReading state information... Done\r\n".into()
        }
        "find"      => {
            // Fake empty find output for common patterns
            if args.contains("-name") && args.contains("*.sh") {
                "/root/backup.sh\r\n/etc/cron.daily/apt-compat\r\n".into()
            } else {
                String::new()
            }
        }
        "grep"      => String::new(),
        "tar" | "gzip" | "gunzip" | "unzip" | "zip" => String::new(),
        "scp" | "ssh" | "sftp" => {
            "ssh: connect to host localhost port 22: Connection refused\r\n".into()
        }
        "ping"      => {
            let host = args.split_whitespace().next().unwrap_or("host");
            format!("PING {host} (93.184.216.34) 56(84) bytes of data.\r\n64 bytes from {host}: icmp_seq=1 ttl=51 time=11.3 ms\r\n^C\r\n")
        }
        "nmap"      => {
            "Starting Nmap 7.80 ( https://nmap.org )\r\nnmap: You requested a scan type which requires root privileges.\r\n".into()
        }
        "exit" | "logout" => String::new(),
        "base64"    => {
            if args.trim().is_empty() || args.contains('-') {
                // Pretend we read stdin and encoded something
                "SGVsbG8gV29ybGQK\r\n".into()
            } else {
                "SGVsbG8gV29ybGQK\r\n".into()
            }
        }
        "xxd"       => String::new(),
        "date"      => {
            let now = chrono::Local::now();
            format!("{}\r\n", now.format("%a %b %e %H:%M:%S %Z %Y"))
        }
        "head"      => vfs.cat(args.split_whitespace().last().unwrap_or("")),
        "tail"      => vfs.cat(args.split_whitespace().last().unwrap_or("")),
        "wc"        => {
            let target = args.split_whitespace().last().unwrap_or("");
            let content = vfs.cat(target);
            let lines = content.lines().count();
            let words = content.split_whitespace().count();
            let bytes = content.len();
            format!(" {lines:>7} {words:>7} {bytes:>7} {target}\r\n")
        }
        "cut"       => String::new(),
        "sort"      => String::new(),
        "uniq"      => String::new(),
        "awk"       => String::new(),
        "sed"       => String::new(),
        "tr"        => String::new(),
        "tee"       => String::new(),
        "xargs"     => String::new(),
        "nc" | "netcat" | "ncat" => {
            "nc: getaddrinfo for host \"\" port 0: Servname not supported for ai_socktype\r\n".into()
        }
        "curl"      => {
            // curl alone (no URL captured by re_download) or curl --help etc.
            if args.trim().is_empty() {
                "curl: try 'curl --help' for more information\r\n".into()
            } else if args.contains("--help") || args.contains("-h") {
                "Usage: curl [options...] <url>\r\nUse 'curl --help category' to get an overview of all categories.\r\n".into()
            } else {
                "curl: (6) Could not resolve host\r\n".into()
            }
        }
        "passwd"    => "Changing password for root.\r\nNew password: ".into(),
        "useradd" | "userdel" | "usermod" | "groupadd" => String::new(),
        "su"        => String::new(),
        "lsof"      => String::new(),
        "strace"    => String::new(),
        "kill" | "killall" | "pkill" => String::new(),
        "mount" | "umount" => String::new(),
        "dmesg"     => "[    0.000000] Initializing cgroup subsys cpuset\r\n[    0.000000] Linux version 5.15.0-72-generic\r\n".into(),
        "journalctl" => "-- No entries --\r\n".into(),
        _ => {
            // Check if it's a path-like execution attempt
            if cmd.starts_with("./") || cmd.starts_with("/") {
                let target = cmd.split_whitespace().next().unwrap_or(cmd);
                let _parts_path = vfs.current_path_str() + "/" + target.trim_start_matches("./");
                format!("bash: {target}: Permission denied\r\n")
            } else {
                format!("bash: {}: command not found\r\n", prog)
            }
        }
    }
}
