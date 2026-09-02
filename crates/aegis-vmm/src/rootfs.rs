//! `aegis-vmm::rootfs` — Golden Rootfs Provisioning.
//!
//! Creates and populates a rich, realistic Ubuntu 22.04 LTS filesystem tree
//! (`bin`, `boot`, `dev`, `etc`, `home`, `lib`, `lib64`, `media`, `mnt`, `opt`,
//! `proc`, `root`, `run`, `sbin`, `srv`, `sys`, `tmp`, `usr`, `var`, etc.)
//! to serve as the authentic read-only `lowerdir` for session OverlayFS sandboxes.

use aegis_common::AegisResult;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::fs;
use tracing::info;

/// Ensures that the golden rootfs exists and is populated with full Ubuntu 22.04 LTS files.
pub async fn ensure_golden_rootfs(base_path: impl AsRef<Path>) -> AegisResult<()> {
    let base = base_path.as_ref();

    info!("Ensuring golden rootfs at {}", base.display());

    // 1. Create standard Ubuntu FHS directory hierarchy
    let dirs = [
        "bin",
        "boot",
        "boot/grub",
        "dev",
        "dev/pts",
        "dev/shm",
        "etc",
        "etc/ssh",
        "etc/network",
        "etc/cron.d",
        "etc/cron.daily",
        "etc/cron.hourly",
        "etc/cron.weekly",
        "etc/cron.monthly",
        "etc/systemd",
        "etc/systemd/system",
        "etc/pam.d",
        "etc/security",
        "etc/default",
        "etc/apt",
        "etc/apt/sources.list.d",
        "home",
        "home/ubuntu",
        "home/ubuntu/.ssh",
        "home/ubuntu/projects",
        "lib",
        "lib64",
        "media",
        "mnt",
        "opt",
        "proc",
        "proc/net",
        "proc/sys/kernel",
        "root",
        "root/.ssh",
        "run",
        "run/sshd",
        "run/systemd",
        "run/user",
        "sbin",
        "srv",
        "sys",
        "sys/class",
        "sys/devices",
        "sys/fs/cgroup",
        "tmp",
        "usr",
        "usr/bin",
        "usr/sbin",
        "usr/lib",
        "usr/lib64",
        "usr/local",
        "usr/local/bin",
        "usr/local/sbin",
        "usr/share",
        "usr/include",
        "var",
        "var/backups",
        "var/cache",
        "var/cache/apt",
        "var/cache/apt/archives",
        "var/lib",
        "var/lib/dpkg",
        "var/lib/systemd",
        "var/local",
        "var/lock",
        "var/log",
        "var/log/nginx",
        "var/log/journal",
        "var/mail",
        "var/opt",
        "var/run",
        "var/spool",
        "var/spool/cron",
        "var/spool/cron/crontabs",
        "var/tmp",
        "var/www",
        "var/www/html",
    ];

    for d in dirs {
        fs::create_dir_all(base.join(d)).await?;
    }

    // Set /tmp and /var/tmp permissions (1777 sticky bit)
    let _ = fs::set_permissions(base.join("tmp"), std::fs::Permissions::from_mode(0o1777)).await;
    let _ = fs::set_permissions(base.join("var/tmp"), std::fs::Permissions::from_mode(0o1777)).await;

    // 2. Populate Configuration Files in /etc
    write_file(
        &base.join("etc/passwd"),
        "root:x:0:0:root:/root:/bin/bash\n\
         daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
         bin:x:2:2:bin:/bin:/usr/sbin/nologin\n\
         sys:x:3:3:sys:/dev:/usr/sbin/nologin\n\
         sync:x:4:65534:sync:/bin:/bin/sync\n\
         games:x:5:60:games:/usr/games:/usr/sbin/nologin\n\
         man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n\
         lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n\
         mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n\
         news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n\
         uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n\
         proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n\
         www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
         backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n\
         list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n\
         nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
         systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n\
         systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n\
         messagebus:x:102:105::/nonexistent:/usr/sbin/nologin\n\
         systemd-timesync:x:103:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\n\
         syslog:x:104:110::/home/syslog:/usr/sbin/nologin\n\
         _apt:x:105:65534::/nonexistent:/usr/sbin/nologin\n\
         sshd:x:106:65534::/run/sshd:/usr/sbin/nologin\n\
         ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n",
        0o644,
    ).await?;

    write_file(
        &base.join("etc/shadow"),
        "root:$6$rounds=4096$Fk9mS...$rO2u.F88z1Ff9a2b8...:19400:0:99999:7:::\n\
         daemon:*:19400:0:99999:7:::\n\
         bin:*:19400:0:99999:7:::\n\
         sys:*:19400:0:99999:7:::\n\
         sync:*:19400:0:99999:7:::\n\
         games:*:19400:0:99999:7:::\n\
         man:*:19400:0:99999:7:::\n\
         lp:*:19400:0:99999:7:::\n\
         mail:*:19400:0:99999:7:::\n\
         news:*:19400:0:99999:7:::\n\
         uucp:*:19400:0:99999:7:::\n\
         proxy:*:19400:0:99999:7:::\n\
         www-data:*:19400:0:99999:7:::\n\
         backup:*:19400:0:99999:7:::\n\
         list:*:19400:0:99999:7:::\n\
         nobody:*:19400:0:99999:7:::\n\
         systemd-network:*:19400:0:99999:7:::\n\
         systemd-resolve:*:19400:0:99999:7:::\n\
         messagebus:*:19400:0:99999:7:::\n\
         systemd-timesync:*:19400:0:99999:7:::\n\
         syslog:*:19400:0:99999:7:::\n\
         _apt:*:19400:0:99999:7:::\n\
         sshd:*:19400:0:99999:7:::\n\
         ubuntu:$6$v8L9Pq1...$Xn8kL0...:19400:0:99999:7:::\n",
        0o640,
    ).await?;

    write_file(
        &base.join("etc/group"),
        "root:x:0:\n\
         daemon:x:1:\n\
         bin:x:2:\n\
         sys:x:3:\n\
         adm:x:4:syslog,ubuntu\n\
         tty:x:5:\n\
         disk:x:6:\n\
         lp:x:7:\n\
         mail:x:8:\n\
         news:x:9:\n\
         uucp:x:10:\n\
         man:x:12:\n\
         proxy:x:13:\n\
         kmem:x:15:\n\
         dialout:x:20:ubuntu\n\
         fax:x:21:\n\
         voice:x:22:\n\
         cdrom:x:24:ubuntu\n\
         floppy:x:25:\n\
         tape:x:26:\n\
         sudo:x:27:ubuntu\n\
         audio:x:29:ubuntu\n\
         dip:x:30:ubuntu\n\
         www-data:x:33:\n\
         backup:x:34:\n\
         operator:x:37:\n\
         src:x:40:\n\
         shadow:x:42:\n\
         utmp:x:43:\n\
         video:x:44:ubuntu\n\
         sasl:x:45:\n\
         plugdev:x:46:ubuntu\n\
         staff:x:50:\n\
         games:x:60:\n\
         users:x:100:\n\
         nogroup:x:65534:\n\
         ubuntu:x:1000:\n",
        0o644,
    ).await?;

    write_file(
        &base.join("etc/hosts"),
        "127.0.0.1 localhost\n\
         127.0.1.1 ubuntu-server-01\n\
         \n\
         # The following lines are desirable for IPv6 capable hosts\n\
         ::1 ip6-localhost ip6-loopback\n\
         fe00::0 ip6-localnet\n\
         ff00::0 ip6-mcastprefix\n\
         ff02::1 ip6-allnodes\n\
         ff02::2 ip6-allrouters\n",
        0o644,
    ).await?;

    write_file(&base.join("etc/hostname"), "ubuntu-server-01\n", 0o644).await?;

    write_file(
        &base.join("etc/os-release"),
        "PRETTY_NAME=\"Ubuntu 22.04.2 LTS\"\n\
         NAME=\"Ubuntu\"\n\
         VERSION_ID=\"22.04\"\n\
         VERSION=\"22.04.2 LTS (Jammy Jellyfish)\"\n\
         VERSION_CODENAME=jammy\n\
         ID=ubuntu\n\
         ID_LIKE=debian\n\
         HOME_URL=\"https://www.ubuntu.com/\"\n\
         SUPPORT_URL=\"https://help.ubuntu.com/\"\n\
         BUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\"\n\
         PRIVACY_POLICY_URL=\"https://www.ubuntu.com/legal/terms-and-policies/privacy-policy\"\n\
         UBUNTU_CODENAME=jammy\n",
        0o644,
    ).await?;

    write_file(
        &base.join("etc/issue"),
        "Ubuntu 22.04.2 LTS \\n \\l\n\n",
        0o644,
    ).await?;

    write_file(
        &base.join("etc/resolv.conf"),
        "# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8).\n\
         nameserver 127.0.0.53\n\
         options edns0 trust-ad\n\
         search localdomain\n",
        0o644,
    ).await?;

    write_file(
        &base.join("etc/crontab"),
        "# /etc/crontab: system-wide crontab\n\
         SHELL=/bin/sh\n\
         PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\
         \n\
         # m h dom mon dow user  command\n\
         17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n\
         25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n\
         47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n\
         52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )\n\
         0 2     * * *   root    /bin/bash /root/backup.sh >> /var/log/backup.log 2>&1\n",
        0o644,
    ).await?;

    write_file(
        &base.join("etc/fstab"),
        "# /etc/fstab: static file system information.\n\
         UUID=3a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d /               ext4    errors=remount-ro 0       1\n\
         /swapfile                                 none            swap    sw              0       0\n",
        0o644,
    ).await?;

    write_file(
        &base.join("etc/sudoers"),
        "Defaults        env_reset\n\
         Defaults        mail_badpass\n\
         Defaults        secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n\
         root    ALL=(ALL:ALL) ALL\n\
         %admin ALL=(ALL) ALL\n\
         %sudo   ALL=(ALL:ALL) ALL\n",
        0o440,
    ).await?;

    write_file(
        &base.join("etc/ssh/sshd_config"),
        "Port 22\n\
         PermitRootLogin yes\n\
         PasswordAuthentication yes\n\
         ChallengeResponseAuthentication no\n\
         UsePAM yes\n\
         X11Forwarding yes\n\
         PrintMotd no\n\
         AcceptEnv LANG LC_*\n\
         Subsystem       sftp    /usr/lib/openssh/sftp-server\n",
        0o644,
    ).await?;

    write_file(
        &base.join("etc/shells"),
        "# /etc/shells: valid login shells\n\
         /bin/sh\n\
         /bin/bash\n\
         /usr/bin/sh\n\
         /usr/bin/bash\n\
         /bin/rbash\n\
         /usr/bin/rbash\n\
         /bin/dash\n\
         /usr/bin/dash\n",
        0o644,
    ).await?;

    write_file(
        &base.join("etc/environment"),
        "PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin\"\n",
        0o644,
    ).await?;

    write_file(
        &base.join("etc/apt/sources.list"),
        "deb http://archive.ubuntu.com/ubuntu jammy main restricted\n\
         deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted\n\
         deb http://archive.ubuntu.com/ubuntu jammy universe\n\
         deb http://archive.ubuntu.com/ubuntu jammy-updates universe\n\
         deb http://security.ubuntu.com/ubuntu jammy-security main restricted\n\
         deb http://security.ubuntu.com/ubuntu jammy-security universe\n",
        0o644,
    ).await?;

    // 3. Populate Fake /proc Files
    write_file(
        &base.join("proc/cpuinfo"),
        "processor\t: 0\n\
         vendor_id\t: GenuineIntel\n\
         cpu family\t: 6\n\
         model\t\t: 142\n\
         model name\t: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n\
         stepping\t: 2\n\
         cpu MHz\t\t: 2400.046\n\
         cache size\t: 30720 KB\n\
         physical id\t: 0\n\
         siblings\t: 2\n\
         core id\t\t: 0\n\
         cpu cores\t: 2\n\
         flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl xtopology cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm cpuid_fault invpcid_single pti fsgsbase bmi1 avx2 smep bmi2 invpcid xsaveopt arat\n\
         bugs\t\t: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs itlb_multihit\n\
         bogomips\t: 4800.09\n\
         clflush size\t: 64\n\
         cache_alignment\t: 64\n\
         address sizes\t: 46 bits physical, 48 bits virtual\n\n\
         processor\t: 1\n\
         vendor_id\t: GenuineIntel\n\
         cpu family\t: 6\n\
         model\t\t: 142\n\
         model name\t: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n\
         stepping\t: 2\n\
         cpu MHz\t\t: 2400.046\n\
         cache size\t: 30720 KB\n\
         physical id\t: 0\n\
         siblings\t: 2\n\
         core id\t\t: 1\n\
         cpu cores\t: 2\n",
        0o444,
    ).await?;

    write_file(
        &base.join("proc/meminfo"),
        "MemTotal:        4016148 kB\n\
         MemFree:         1845120 kB\n\
         MemAvailable:    2954312 kB\n\
         Buffers:          124508 kB\n\
         Cached:          1156824 kB\n\
         SwapCached:            0 kB\n\
         Active:          1250140 kB\n\
         Inactive:         754210 kB\n\
         SwapTotal:       2097148 kB\n\
         SwapFree:        2097148 kB\n",
        0o444,
    ).await?;

    write_file(
        &base.join("proc/version"),
        "Linux version 5.15.0-72-generic (buildd@lcy02-amd64-019) (gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #79-Ubuntu SMP Wed Apr 19 08:22:18 UTC 2023\n",
        0o444,
    ).await?;

    write_file(&base.join("proc/uptime"), "84321.45 167234.12\n", 0o444).await?;
    write_file(&base.join("proc/loadavg"), "0.08 0.03 0.01 1/148 2841\n", 0o444).await?;

    // 4. Populate /root and /home/ubuntu directories
    write_file(
        &base.join("root/.bashrc"),
        "# ~/.bashrc: executed by bash(1) for non-login shells.\n\
         export PS1='\\[\\e]0;\\u@\\h: \\w\\a\\]\\u@\\h:\\w\\# '\n\
         alias ls='ls --color=auto'\n\
         alias ll='ls -alF'\n\
         alias la='ls -A'\n\
         alias l='ls -CF'\n",
        0o644,
    ).await?;

    write_file(
        &base.join("root/.profile"),
        "# ~/.profile: executed by Bourne-compatible login shells.\n\
         if [ \"$BASH\" ]; then\n\
           if [ -f ~/.bashrc ]; then\n\
             . ~/.bashrc\n\
           fi\n\
         fi\n\
         mesg n 2> /dev/null || true\n",
        0o644,
    ).await?;

    write_file(
        &base.join("root/.bash_history"),
        "apt-get update\n\
         systemctl status nginx\n\
         docker ps\n\
         cat /etc/hosts\n\
         ufw status\n\
         ls -la /root\n",
        0o600,
    ).await?;

    write_file(
        &base.join("root/backup.sh"),
        "#!/bin/bash\n\
         # Daily automated system backup\n\
         tar -czf /var/backups/system_$(date +%Y%m%d).tar.gz /etc /var/www 2>/dev/null\n",
        0o750,
    ).await?;

    write_file(
        &base.join("home/ubuntu/.bashrc"),
        "export PS1='\\[\\e]0;\\u@\\h: \\w\\a\\]\\u@\\h:\\w\\$ '\n\
         alias ls='ls --color=auto'\n",
        0o644,
    ).await?;

    write_file(
        &base.join("home/ubuntu/projects/README.txt"),
        "Internal development projects directory.\n",
        0o644,
    ).await?;

    // 5. Populate /var/www/html and logs
    write_file(
        &base.join("var/www/html/index.html"),
        "<!DOCTYPE html>\n\
         <html>\n\
         <head><title>Welcome to nginx!</title></head>\n\
         <body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed.</p></body>\n\
         </html>\n",
        0o644,
    ).await?;

    write_file(
        &base.join("var/log/auth.log"),
        "Aug 27 18:00:01 ubuntu-server-01 CRON[1402]: pam_unix(cron:session): session opened for user root by (uid=0)\n\
         Aug 27 18:00:01 ubuntu-server-01 CRON[1402]: pam_unix(cron:session): session closed for user root\n\
         Aug 27 18:25:01 ubuntu-server-01 sshd[1842]: Accepted password for root from 192.0.2.100 port 52341 ssh2\n",
        0o640,
    ).await?;

    write_file(
        &base.join("var/log/syslog"),
        "Aug 27 18:00:01 ubuntu-server-01 systemd[1]: Starting Daily apt download activities...\n\
         Aug 27 18:00:02 ubuntu-server-01 systemd[1]: Finished Daily apt download activities.\n",
        0o640,
    ).await?;

    // 6. Create realistic dummy executable stubs in /bin and /usr/bin
    let bin_names = [
        "bash", "sh", "dash", "ls", "cat", "cp", "mv", "rm", "mkdir", "rmdir", "touch",
        "chmod", "chown", "uname", "id", "whoami", "hostname", "ps", "kill", "pkill",
        "grep", "find", "sed", "awk", "cut", "head", "tail", "wc", "sort", "uniq",
        "echo", "date", "sleep", "which", "curl", "wget", "python3", "python", "perl",
        "sudo", "su", "passwd", "crontab", "tar", "gzip", "base64", "xxd", "nc", "netcat",
        "ping", "netstat", "ss", "ifconfig", "ip", "df", "free", "uptime", "dmesg",
        "systemctl", "service", "journalctl", "apt", "apt-get", "dpkg", "nmap",
    ];

    for name in bin_names {
        let stub = format!("#!/bin/sh\n# Aegis sandbox stub: {name}\nexit 0\n");
        write_file(&base.join(format!("bin/{name}")), &stub, 0o755).await?;
        write_file(&base.join(format!("usr/bin/{name}")), &stub, 0o755).await?;
    }

    info!("Golden rootfs provisioning complete at {}", base.display());
    Ok(())
}

async fn write_file(path: &Path, content: &str, mode: u32) -> AegisResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    if path.exists() {
        let _ = fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).await;
    }
    fs::write(path, content.as_bytes()).await?;
    let _ = fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_golden_rootfs_provisioning() {
        let temp_dir = std::env::temp_dir().join(format!("aegis_test_rootfs_{}", uuid::Uuid::new_v4()));
        let res = ensure_golden_rootfs(&temp_dir).await;
        assert!(res.is_ok());

        assert!(temp_dir.join("etc/passwd").exists());
        assert!(temp_dir.join("etc/os-release").exists());
        assert!(temp_dir.join("proc/cpuinfo").exists());
        assert!(temp_dir.join("bin/bash").exists());
        assert!(temp_dir.join("usr/bin/python3").exists());

        let os_release = tokio::fs::read_to_string(temp_dir.join("etc/os-release")).await.unwrap();
        assert!(os_release.contains("Ubuntu 22.04"));

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
