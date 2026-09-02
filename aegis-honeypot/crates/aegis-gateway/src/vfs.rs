//! VFS module — Virtual File System with live OverlayFS mount & golden rootfs backing.
//!
//! Each session receives an isolated `VirtualFileSystem` instance.
//! Reads seamlessly merge the session's live `upper` mount layer with the golden `rootfs`,
//! providing a 100% authentic Ubuntu 22.04 LTS filesystem view (`/bin`, `/boot`, `/dev`,
//! `/etc`, `/home`, `/lib`, `/lib64`, `/proc`, `/root`, `/sys`, `/tmp`, `/usr`, `/var`).

use std::collections::HashMap;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Node Types (in-memory representation & fallback)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum FsNode {
    File(FileNode),
    Dir(DirNode),
}

#[derive(Debug, Clone)]
pub struct FileNode {
    pub content: String,
    pub perms: String,
    #[allow(dead_code)]
    pub owner: String,
    pub group: String,
    #[allow(dead_code)]
    pub mtime: String,
    pub permission_denied: bool,
}

#[derive(Debug, Clone)]
pub struct DirNode {
    pub perms: String,
    pub owner: String,
    pub group: String,
    #[allow(dead_code)]
    pub mtime: String,
    pub children: HashMap<String, FsNode>,
}

impl FileNode {
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            perms: "-rw-r--r--".into(),
            owner: "root".into(),
            group: "root".into(),
            mtime: "Aug 27 18:00".into(),
            permission_denied: false,
        }
    }
    pub fn denied(mut self) -> Self {
        self.permission_denied = true;
        self.perms = "-rw-r-----".into();
        self.group = "shadow".into();
        self
    }
}

impl DirNode {
    pub fn new() -> Self {
        Self {
            perms: "drwxr-xr-x".into(),
            owner: "root".into(),
            group: "root".into(),
            mtime: "Aug 27 18:00".into(),
            children: HashMap::new(),
        }
    }
    pub fn with_perms(mut self, p: &str) -> Self { self.perms = p.into(); self }
    #[allow(dead_code)]
    pub fn with_owner(mut self, o: &str) -> Self { self.owner = o.into(); self }
    #[allow(dead_code)]
    pub fn with_group(mut self, g: &str) -> Self { self.group = g.into(); self }
    pub fn insert(mut self, name: &str, node: FsNode) -> Self {
        self.children.insert(name.into(), node);
        self
    }
}

macro_rules! file { ($c:expr) => { FsNode::File(FileNode::new($c)) }; }
macro_rules! dir { ($d:expr) => { FsNode::Dir($d) }; }

// ---------------------------------------------------------------------------
// VirtualFileSystem
// ---------------------------------------------------------------------------

pub struct VirtualFileSystem {
    pub current_path: Vec<String>,
    pub mount_root: Option<PathBuf>,
    pub lower_root: Option<PathBuf>,
    root: DirNode,
}

impl Default for VirtualFileSystem {
    fn default() -> Self {
        Self {
            current_path: vec!["root".into()],
            mount_root: None,
            lower_root: None,
            root: build_default_fs(),
        }
    }
}

impl VirtualFileSystem {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_roots(mount_root: Option<PathBuf>, lower_root: Option<PathBuf>) -> Self {
        Self {
            current_path: vec!["root".into()],
            mount_root,
            lower_root,
            root: build_default_fs(),
        }
    }

    #[allow(dead_code)]
    pub fn with_mount_root(mount_root: Option<PathBuf>) -> Self {
        Self {
            current_path: vec!["root".into()],
            mount_root,
            lower_root: Some(PathBuf::from("./rootfs")),
            root: build_default_fs(),
        }
    }

    pub fn current_path_str(&self) -> String {
        if self.current_path.is_empty() {
            "/".into()
        } else {
            format!("/{}", self.current_path.join("/"))
        }
    }

    /// Resolve relative or absolute path tokens into normalized virtual path parts.
    pub fn resolve(&self, path: &str) -> Vec<String> {
        let path = path.trim();
        if path.is_empty() {
            return self.current_path.clone();
        }

        let mut parts = if path.starts_with('/') {
            Vec::new()
        } else if path.starts_with('~') {
            let mut p = vec!["root".to_owned()];
            let rest = path.trim_start_matches('~').trim_start_matches('/');
            if !rest.is_empty() {
                for comp in rest.split('/') {
                    if !comp.is_empty() && comp != "." {
                        p.push(comp.to_owned());
                    }
                }
            }
            return p;
        } else {
            self.current_path.clone()
        };

        for component in path.split('/') {
            match component {
                "" | "." => {}
                ".." => { parts.pop(); }
                c => parts.push(c.to_owned()),
            }
        }
        parts
    }

    /// Safely resolve virtual path parts to a real filesystem path inside a given base.
    pub fn resolve_disk_path_base(&self, base: &PathBuf, parts: &[String]) -> PathBuf {
        let mut full = base.clone();
        for part in parts {
            if part.is_empty() || part == "." || part == ".." || part.contains('/') {
                continue;
            }
            full.push(part);
        }
        full
    }

    /// Safely resolve to upper/mount directory path.
    pub fn resolve_upper_path(&self, parts: &[String]) -> Option<PathBuf> {
        let base = self.mount_root.as_ref()?;
        Some(self.resolve_disk_path_base(base, parts))
    }

    /// Safely resolve to lower/golden rootfs directory path.
    pub fn resolve_lower_path(&self, parts: &[String]) -> Option<PathBuf> {
        let base = self.lower_root.as_ref()?;
        Some(self.resolve_disk_path_base(base, parts))
    }

    fn get_dir_mut(&mut self, parts: &[String]) -> Option<&mut DirNode> {
        let mut dir = &mut self.root;
        for part in parts {
            match dir.children.get_mut(part) {
                Some(FsNode::Dir(d)) => dir = d,
                _ => return None,
            }
        }
        Some(dir)
    }

    fn get_node_safe(&self, parts: &[String]) -> Option<FsNode> {
        if parts.is_empty() {
            return Some(FsNode::Dir(self.root.clone()));
        }
        let mut dir = &self.root;
        for (i, part) in parts.iter().enumerate() {
            match dir.children.get(part) {
                None => return None,
                Some(node) => {
                    if i == parts.len() - 1 {
                        return Some(node.clone());
                    }
                    match node {
                        FsNode::Dir(d) => dir = d,
                        FsNode::File(_) => return None,
                    }
                }
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // Core Shell Commands
    // -----------------------------------------------------------------------

    pub fn pwd(&self) -> String {
        format!("{}\r\n", self.current_path_str())
    }

    pub fn cd(&mut self, arg: &str) -> String {
        let arg = arg.trim();
        let parts = if arg.is_empty() { vec!["root".into()] } else { self.resolve(arg) };

        if parts.is_empty() {
            self.current_path = parts;
            return String::new();
        }

        // 1. Check upper disk path
        if let Some(upper) = self.resolve_upper_path(&parts) {
            if upper.exists() {
                if upper.is_dir() {
                    self.current_path = parts;
                    return String::new();
                } else {
                    return format!("bash: cd: {arg}: Not a directory\r\n");
                }
            }
        }

        // 2. Check lower disk path
        if let Some(lower) = self.resolve_lower_path(&parts) {
            if lower.exists() {
                if lower.is_dir() {
                    self.current_path = parts;
                    return String::new();
                } else {
                    return format!("bash: cd: {arg}: Not a directory\r\n");
                }
            }
        }

        // 3. Fallback to in-memory node check
        match self.get_node_safe(&parts) {
            Some(FsNode::Dir(_)) => {
                self.current_path = parts;
                String::new()
            }
            Some(FsNode::File(_)) => format!("bash: cd: {arg}: Not a directory\r\n"),
            None => format!("bash: cd: {arg}: No such file or directory\r\n"),
        }
    }

    pub fn ls(&self, args: &str) -> String {
        let tokens: Vec<&str> = args.split_whitespace().collect();
        let mut flags = String::new();
        let mut targets: Vec<&str> = vec![];

        for t in &tokens {
            if t.starts_with('-') { flags.push_str(&t[1..]); }
            else { targets.push(t); }
        }

        let show_hidden = flags.contains('a') || flags.contains('A');
        let long = flags.contains('l');

        let list_targets: Vec<Vec<String>> = if targets.is_empty() {
            vec![self.current_path.clone()]
        } else {
            targets.iter().map(|t| self.resolve(t)).collect()
        };

        let mut output = String::new();

        for parts in list_targets {
            // Check if target is a single file on disk
            if let Some(upper) = self.resolve_upper_path(&parts) {
                if upper.is_file() {
                    let name = parts.last().map(|s| s.as_str()).unwrap_or("?");
                    let size = std::fs::metadata(&upper).map(|m| m.len()).unwrap_or(0);
                    if long {
                        output.push_str(&format!("-rw-r--r-- 1 root root {:>5} Aug 27 18:00 {name}\r\n", size));
                    } else {
                        output.push_str(&format!("{name}\r\n"));
                    }
                    continue;
                }
            }
            if let Some(lower) = self.resolve_lower_path(&parts) {
                if lower.is_file() {
                    let name = parts.last().map(|s| s.as_str()).unwrap_or("?");
                    let size = std::fs::metadata(&lower).map(|m| m.len()).unwrap_or(0);
                    if long {
                        output.push_str(&format!("-rw-r--r-- 1 root root {:>5} Aug 27 18:00 {name}\r\n", size));
                    } else {
                        output.push_str(&format!("{name}\r\n"));
                    }
                    continue;
                }
            }

            // Gather all entries merged from: upper, lower, and in-memory
            let mut entries_map: HashMap<String, (String, u64, bool)> = HashMap::new();

            // 1. In-memory entries
            if let Some(FsNode::Dir(d)) = self.get_node_safe(&parts) {
                for (name, node) in d.children {
                    let (perms, size, is_dir) = match node {
                        FsNode::File(f) => (f.perms, f.content.len() as u64, false),
                        FsNode::Dir(d) => (d.perms, 4096, true),
                    };
                    entries_map.insert(name, (perms, size, is_dir));
                }
            }

            // 2. Lower disk entries (golden rootfs)
            if let Some(lower) = self.resolve_lower_path(&parts) {
                if lower.is_dir() {
                    if let Ok(iter) = std::fs::read_dir(&lower) {
                        for entry in iter.filter_map(|e| e.ok()) {
                            let name = entry.file_name().to_string_lossy().into_owned();
                            let is_dir = entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
                            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                            let perms = if is_dir { "drwxr-xr-x" } else { "-rw-r--r--" };
                            entries_map.insert(name, (perms.into(), if is_dir { 4096 } else { size }, is_dir));
                        }
                    }
                }
            }

            // 3. Upper disk entries (attacker session overrides)
            if let Some(upper) = self.resolve_upper_path(&parts) {
                if upper.is_dir() {
                    if let Ok(iter) = std::fs::read_dir(&upper) {
                        for entry in iter.filter_map(|e| e.ok()) {
                            let name = entry.file_name().to_string_lossy().into_owned();
                            let is_dir = entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
                            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                            let perms = if is_dir { "drwxr-xr-x" } else { "-rw-r--r--" };
                            entries_map.insert(name, (perms.into(), if is_dir { 4096 } else { size }, is_dir));
                        }
                    }
                }
            }

            if entries_map.is_empty() && !parts.is_empty() && self.get_node_safe(&parts).is_none() {
                output.push_str(&format!("ls: cannot access '{}': No such file or directory\r\n",
                    if parts.is_empty() { "/".to_owned() } else { format!("/{}", parts.join("/")) }
                ));
                continue;
            }

            let mut sorted_names: Vec<String> = entries_map.keys().cloned().collect();
            sorted_names.sort();

            let mut final_entries: Vec<(String, String, u64, bool)> = vec![];
            if show_hidden {
                final_entries.push((".".into(), "drwxr-xr-x".into(), 4096, true));
                final_entries.push(("..".into(), "drwxr-xr-x".into(), 4096, true));
            }

            for name in sorted_names {
                if !show_hidden && name.starts_with('.') { continue; }
                if let Some((perms, size, is_dir)) = entries_map.get(&name) {
                    final_entries.push((name, perms.clone(), *size, *is_dir));
                }
            }

            if long {
                output.push_str(&format!("total {}\r\n", final_entries.len() * 4));
                for (name, perms, size, is_dir) in &final_entries {
                    let links = if *is_dir { 2 } else { 1 };
                    output.push_str(&format!("{perms} {links} root root {size:>5} Aug 27 18:00 {name}\r\n"));
                }
            } else {
                let names: Vec<&str> = final_entries.iter().map(|(n, ..)| n.as_str()).collect();
                if !names.is_empty() {
                    output.push_str(&format!("{}\r\n", names.join("  ")));
                }
            }
        }
        output
    }

    pub fn cat(&self, args: &str) -> String {
        let targets: Vec<&str> = args.split_whitespace().filter(|t| !t.starts_with('-')).collect();
        if targets.is_empty() { return String::new(); }

        let mut output = String::new();
        for target in targets {
            let parts = self.resolve(target);

            // Permission check on shadow
            if target.contains("shadow") {
                output.push_str(&format!("cat: {target}: Permission denied\r\n"));
                continue;
            }

            // 1. Check upper disk
            if let Some(upper) = self.resolve_upper_path(&parts) {
                if upper.exists() {
                    if upper.is_dir() {
                        output.push_str(&format!("cat: {target}: Is a directory\r\n"));
                        continue;
                    }
                    if let Ok(content) = std::fs::read_to_string(&upper) {
                        let c = content.replace("\r\n", "\n").replace('\n', "\r\n");
                        output.push_str(&c);
                        if !c.ends_with("\r\n") { output.push_str("\r\n"); }
                        continue;
                    }
                }
            }

            // 2. Check lower disk
            if let Some(lower) = self.resolve_lower_path(&parts) {
                if lower.exists() {
                    if lower.is_dir() {
                        output.push_str(&format!("cat: {target}: Is a directory\r\n"));
                        continue;
                    }
                    if let Ok(content) = std::fs::read_to_string(&lower) {
                        let c = content.replace("\r\n", "\n").replace('\n', "\r\n");
                        output.push_str(&c);
                        if !c.ends_with("\r\n") { output.push_str("\r\n"); }
                        continue;
                    }
                }
            }

            // 3. Fallback to in-memory node
            match self.get_node_safe(&parts) {
                None => output.push_str(&format!("cat: {target}: No such file or directory\r\n")),
                Some(FsNode::Dir(_)) => output.push_str(&format!("cat: {target}: Is a directory\r\n")),
                Some(FsNode::File(f)) => {
                    if f.permission_denied {
                        output.push_str(&format!("cat: {target}: Permission denied\r\n"));
                    } else {
                        let c = f.content.replace("\r\n", "\n").replace('\n', "\r\n");
                        output.push_str(&c);
                        if !c.ends_with("\r\n") { output.push_str("\r\n"); }
                    }
                }
            }
        }
        output
    }

    pub fn mkdir(&mut self, args: &str) -> String {
        let tokens: Vec<&str> = args.split_whitespace().collect();
        let parents = tokens.iter().any(|t| *t == "-p");
        let targets: Vec<&str> = tokens.iter().filter(|t| !t.starts_with('-')).copied().collect();

        if targets.is_empty() { return "mkdir: missing operand\r\n".into(); }

        let mut output = String::new();
        for target in targets {
            let parts = self.resolve(target);
            if parts.is_empty() {
                output.push_str("mkdir: cannot create directory '/': File exists\r\n");
                continue;
            }

            // Real disk creation in upperdir
            if let Some(upper) = self.resolve_upper_path(&parts) {
                if parents {
                    let _ = std::fs::create_dir_all(&upper);
                } else if upper.exists() {
                    output.push_str(&format!("mkdir: cannot create directory '{target}': File exists\r\n"));
                    continue;
                } else if let Some(parent) = upper.parent() {
                    let _ = std::fs::create_dir_all(parent);
                    let _ = std::fs::create_dir(&upper);
                }
            }

            // In-memory update
            if parents {
                let mut dir = &mut self.root;
                for p in &parts {
                    if !dir.children.contains_key(p.as_str()) {
                        dir.children.insert(p.clone(), dir!(DirNode::new()));
                    }
                    dir = match dir.children.get_mut(p) {
                        Some(FsNode::Dir(d)) => d,
                        _ => break,
                    };
                }
            } else {
                let parent_parts = &parts[..parts.len()-1];
                let name = parts.last().unwrap().clone();
                if let Some(parent) = self.get_dir_mut(parent_parts) {
                    if parent.children.contains_key(&name) {
                        if output.is_empty() {
                            output.push_str(&format!("mkdir: cannot create directory '{target}': File exists\r\n"));
                        }
                    } else {
                        parent.children.insert(name, dir!(DirNode::new()));
                    }
                } else if output.is_empty() {
                    output.push_str(&format!("mkdir: cannot create directory '{target}': No such file or directory\r\n"));
                }
            }
        }
        output
    }

    pub fn touch(&mut self, args: &str) -> String {
        let targets: Vec<&str> = args.split_whitespace().filter(|t| !t.starts_with('-')).collect();
        if targets.is_empty() { return "touch: missing file operand\r\n".into(); }

        for target in targets {
            let parts = self.resolve(target);
            if parts.is_empty() { continue; }

            // Real disk creation in upperdir
            if let Some(upper) = self.resolve_upper_path(&parts) {
                if let Some(parent) = upper.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::OpenOptions::new().create(true).write(true).open(&upper);
            }

            // In-memory update
            let parent_parts = &parts[..parts.len()-1];
            let name = parts.last().unwrap().clone();
            if let Some(parent) = self.get_dir_mut(parent_parts) {
                if !parent.children.contains_key(&name) {
                    parent.children.insert(name, file!(""));
                }
            }
        }
        String::new()
    }

    pub fn rm(&mut self, args: &str) -> String {
        let tokens: Vec<&str> = args.split_whitespace().collect();
        let recursive = tokens.iter().any(|t| t.contains('r') || t.contains('R'));
        let force = tokens.iter().any(|t| t.contains('f'));
        let targets: Vec<&str> = tokens.iter().filter(|t| !t.starts_with('-')).copied().collect();

        if targets.is_empty() {
            if force { return String::new(); }
            return "rm: missing operand\r\n".into();
        }

        let mut output = String::new();
        for target in targets {
            let parts = self.resolve(target);
            if parts.is_empty() {
                output.push_str("rm: it is dangerous to operate recursively on '/'\r\n");
                continue;
            }

            // Real disk removal in upperdir
            if let Some(upper) = self.resolve_upper_path(&parts) {
                if upper.exists() {
                    if upper.is_dir() {
                        if recursive {
                            let _ = std::fs::remove_dir_all(&upper);
                        } else if !force {
                            output.push_str(&format!("rm: cannot remove '{target}': Is a directory\r\n"));
                            continue;
                        }
                    } else {
                        let _ = std::fs::remove_file(&upper);
                    }
                }
            }

            // In-memory removal
            let parent_parts = &parts[..parts.len()-1];
            let name = parts.last().unwrap().clone();
            if let Some(parent) = self.get_dir_mut(parent_parts) {
                if let Some(node) = parent.children.get(&name) {
                    match node {
                        FsNode::Dir(_) if !recursive => {
                            if !force && output.is_empty() {
                                output.push_str(&format!("rm: cannot remove '{target}': Is a directory\r\n"));
                            }
                        }
                        _ => {
                            parent.children.remove(&name);
                        }
                    }
                } else if !force && output.is_empty() {
                    output.push_str(&format!("rm: cannot remove '{target}': No such file or directory\r\n"));
                }
            }
        }
        output
    }

    pub fn write_file(&mut self, target: &str, content: &str, append: bool) -> String {
        let parts = self.resolve(target);
        if parts.is_empty() {
            return format!("bash: {target}: Is a directory\r\n");
        }

        // Real disk write in upperdir
        if let Some(upper) = self.resolve_upper_path(&parts) {
            if let Some(parent) = upper.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if append {
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&upper) {
                    let _ = f.write_all(content.as_bytes());
                }
            } else {
                let _ = std::fs::write(&upper, content.as_bytes());
            }
        }

        // In-memory write
        let parent_parts = &parts[..parts.len()-1];
        let name = parts.last().unwrap().clone();
        if let Some(parent) = self.get_dir_mut(parent_parts) {
            if append {
                if let Some(FsNode::File(f)) = parent.children.get_mut(&name) {
                    f.content.push_str(content);
                } else {
                    parent.children.insert(name, file!(content));
                }
            } else {
                parent.children.insert(name, file!(content));
            }
        }
        String::new()
    }
}

// ---------------------------------------------------------------------------
// In-Memory Default Hierarchy (complete Ubuntu 22.04 LTS filesystem)
// ---------------------------------------------------------------------------

fn build_default_fs() -> DirNode {
    DirNode::new()
        .insert("bin", dir!(DirNode::new()
            .insert("bash", file!(""))
            .insert("sh", file!(""))
            .insert("ls", file!(""))
            .insert("cat", file!(""))
            .insert("cp", file!(""))
            .insert("mv", file!(""))
            .insert("rm", file!(""))
            .insert("mkdir", file!(""))
            .insert("chmod", file!(""))
            .insert("chown", file!(""))
            .insert("uname", file!(""))
            .insert("id", file!(""))
            .insert("whoami", file!(""))
            .insert("hostname", file!(""))
            .insert("ps", file!(""))
            .insert("grep", file!(""))
            .insert("echo", file!(""))
            .insert("date", file!(""))
            .insert("curl", file!(""))
            .insert("wget", file!(""))
            .insert("python3", file!(""))
        ))
        .insert("boot", dir!(DirNode::new()
            .insert("vmlinuz-5.15.0-72-generic", file!(""))
            .insert("initrd.img-5.15.0-72-generic", file!(""))
            .insert("config-5.15.0-72-generic", file!(""))
            .insert("System.map-5.15.0-72-generic", file!(""))
            .insert("grub", dir!(DirNode::new()
                .insert("grub.cfg", file!("# GRUB configuration file\n"))
            ))
        ))
        .insert("dev", dir!(DirNode::new()
            .insert("null", file!(""))
            .insert("zero", file!(""))
            .insert("urandom", file!(""))
            .insert("random", file!(""))
            .insert("tty", file!(""))
            .insert("pts", dir!(DirNode::new()))
            .insert("shm", dir!(DirNode::new()))
            .insert("sda", file!(""))
            .insert("sda1", file!(""))
        ))
        .insert("etc", dir!(DirNode::new()
            .insert("passwd", file!("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nsshd:x:106:65534::/run/sshd:/usr/sbin/nologin\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"))
            .insert("shadow", FsNode::File(FileNode::new("root:*:19400:0:99999:7:::\nubuntu:$6$fakesalt$encryptedhash:19400:0:99999:7:::\n").denied()))
            .insert("group", file!("root:x:0:\ndaemon:x:1:\nadm:x:4:syslog,ubuntu\nsudo:x:27:ubuntu\nwww-data:x:33:\nshadow:x:42:\nubuntu:x:1000:\n"))
            .insert("hosts", file!("127.0.0.1 localhost\n127.0.1.1 ubuntu-server-01\n::1 ip6-localhost ip6-loopback\n"))
            .insert("hostname", file!("ubuntu-server-01\n"))
            .insert("os-release", file!("NAME=\"Ubuntu\"\nVERSION=\"22.04.2 LTS (Jammy Jellyfish)\"\nID=ubuntu\nPRETTY_NAME=\"Ubuntu 22.04.2 LTS\"\nVERSION_ID=\"22.04\"\n"))
            .insert("issue", file!("Ubuntu 22.04.2 LTS \\n \\l\n\n"))
            .insert("resolv.conf", file!("nameserver 127.0.0.53\noptions edns0 trust-ad\n"))
            .insert("crontab", file!("# /etc/crontab\n0 2 * * *  root /bin/bash /root/backup.sh >> /var/log/backup.log 2>&1\n"))
            .insert("fstab", file!("UUID=3a1b2c3d / ext4 errors=remount-ro 0 1\n"))
            .insert("sudoers", file!("root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n"))
            .insert("shells", file!("/bin/sh\n/bin/bash\n/usr/bin/sh\n/usr/bin/bash\n"))
            .insert("environment", file!("PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n"))
            .insert("ssh", dir!(DirNode::new()
                .insert("sshd_config", file!("Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding yes\n"))
            ))
            .insert("network", dir!(DirNode::new()
                .insert("interfaces", file!("auto lo\niface lo inet loopback\n"))
            ))
            .insert("apt", dir!(DirNode::new()
                .insert("sources.list", file!("deb http://archive.ubuntu.com/ubuntu jammy main restricted\n"))
            ))
        ))
        .insert("home", dir!(DirNode::new()
            .insert("ubuntu", dir!(DirNode::new()
                .insert(".bashrc", file!("export PS1='\\u@\\h:\\w\\$ '\n"))
                .insert(".profile", file!(""))
                .insert(".ssh", dir!(DirNode::new()))
                .insert("projects", dir!(DirNode::new()
                    .insert("README.txt", file!("Internal development projects.\n"))
                ))
            ))
        ))
        .insert("lib", dir!(DirNode::new()
            .insert("x86_64-linux-gnu", dir!(DirNode::new()))
            .insert("modules", dir!(DirNode::new()
                .insert("5.15.0-72-generic", dir!(DirNode::new()))
            ))
        ))
        .insert("lib64", dir!(DirNode::new()
            .insert("ld-linux-x86-64.so.2", file!(""))
        ))
        .insert("media", dir!(DirNode::new()))
        .insert("mnt", dir!(DirNode::new()))
        .insert("opt", dir!(DirNode::new()))
        .insert("proc", dir!(DirNode::new()
            .insert("cpuinfo", file!("processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\ncpu cores\t: 2\n"))
            .insert("meminfo", file!("MemTotal:        4016148 kB\nMemFree:         1845120 kB\nMemAvailable:    2954312 kB\n"))
            .insert("version", file!("Linux version 5.15.0-72-generic (buildd@lcy02-amd64-019) (gcc 11.3.0) #79-Ubuntu SMP Wed Apr 19 08:22:18 UTC 2023\n"))
            .insert("uptime", file!("84321.45 167234.12\n"))
            .insert("loadavg", file!("0.08 0.03 0.01 1/148 2841\n"))
            .insert("mounts", file!("rootfs / rootfs rw 0 0\nsysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"))
            .insert("net", dir!(DirNode::new()
                .insert("dev", file!("Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 1234567     890    0    0    0     0          0         0  1234567     890    0    0    0     0       0          0\n  eth0: 9876543    4567    0    0    0     0          0         0  9876543    4567    0    0    0     0       0          0\n"))
            ))
            .insert("sys", dir!(DirNode::new()
                .insert("kernel", dir!(DirNode::new()
                    .insert("hostname", file!("ubuntu-server-01\n"))
                    .insert("osrelease", file!("5.15.0-72-generic\n"))
                ))
            ))
        ))
        .insert("root", dir!(DirNode::new()
            .insert(".bashrc", file!("# ~/.bashrc\nexport PS1='\\u@\\h:\\w\\# '\nalias ls='ls --color=auto'\n"))
            .insert(".profile", file!(""))
            .insert(".bash_history", file!("apt-get update\nsystemctl status nginx\ndocker ps\ncat /etc/hosts\nufw status\nls -la /root\n"))
            .insert(".ssh", dir!(DirNode::new()
                .insert("authorized_keys", file!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey root@mgmt\n"))
            ))
            .insert("backup.sh", file!("#!/bin/bash\ntar -czf /var/backups/system_backup.tar.gz /etc /var/www\n"))
        ))
        .insert("run", dir!(DirNode::new()
            .insert("sshd.pid", file!("1042\n"))
            .insert("systemd", dir!(DirNode::new()))
            .insert("lock", dir!(DirNode::new()))
        ))
        .insert("sbin", dir!(DirNode::new()
            .insert("init", file!(""))
            .insert("reboot", file!(""))
            .insert("shutdown", file!(""))
            .insert("iptables", file!(""))
            .insert("ip", file!(""))
            .insert("ifconfig", file!(""))
            .insert("fdisk", file!(""))
        ))
        .insert("srv", dir!(DirNode::new()))
        .insert("sys", dir!(DirNode::new()
            .insert("class", dir!(DirNode::new()))
            .insert("devices", dir!(DirNode::new()))
            .insert("fs", dir!(DirNode::new()
                .insert("cgroup", dir!(DirNode::new()))
            ))
        ))
        .insert("tmp", dir!(DirNode::new().with_perms("drwxrwxrwt")))
        .insert("usr", dir!(DirNode::new()
            .insert("bin", dir!(DirNode::new()
                .insert("python3", file!(""))
                .insert("curl", file!(""))
                .insert("wget", file!(""))
                .insert("sudo", file!(""))
                .insert("apt", file!(""))
                .insert("apt-get", file!(""))
                .insert("systemctl", file!(""))
                .insert("netstat", file!(""))
                .insert("ss", file!(""))
                .insert("nc", file!(""))
                .insert("base64", file!(""))
                .insert("xxd", file!(""))
                .insert("awk", file!(""))
                .insert("sed", file!(""))
            ))
            .insert("sbin", dir!(DirNode::new()
                .insert("sshd", file!(""))
                .insert("service", file!(""))
            ))
            .insert("lib", dir!(DirNode::new()))
            .insert("local", dir!(DirNode::new()
                .insert("bin", dir!(DirNode::new()))
                .insert("sbin", dir!(DirNode::new()))
            ))
            .insert("share", dir!(DirNode::new()))
        ))
        .insert("var", dir!(DirNode::new()
            .insert("backups", dir!(DirNode::new()))
            .insert("cache", dir!(DirNode::new()
                .insert("apt", dir!(DirNode::new()))
            ))
            .insert("lib", dir!(DirNode::new()
                .insert("dpkg", dir!(DirNode::new()))
            ))
            .insert("log", dir!(DirNode::new()
                .insert("auth.log", file!("Aug 27 18:00:01 ubuntu-server-01 CRON[1402]: pam_unix(cron:session): session opened for user root\n"))
                .insert("syslog", file!("Aug 27 18:00:01 ubuntu-server-01 systemd[1]: Starting Daily apt download activities...\n"))
                .insert("dpkg.log", file!("2026-08-20 14:00:00 status installed linux-image-5.15.0-72-generic:amd64\n"))
                .insert("nginx", dir!(DirNode::new()
                    .insert("access.log", file!("192.0.2.100 - - [27/Aug/2026:18:00:00 +0000] \"GET / HTTP/1.1\" 200 612\n"))
                ))
            ))
            .insert("run", dir!(DirNode::new()))
            .insert("spool", dir!(DirNode::new()))
            .insert("tmp", dir!(DirNode::new().with_perms("drwxrwxrwt")))
            .insert("www", dir!(DirNode::new()
                .insert("html", dir!(DirNode::new()
                    .insert("index.html", file!("<!DOCTYPE html><html><body><h1>Welcome to nginx!</h1></body></html>\n"))
                ))
            ))
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vfs_live_disk_operations() {
        let temp_dir = std::env::temp_dir().join(format!("aegis_test_vfs_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(temp_dir.join("root")).unwrap();
        std::fs::create_dir_all(temp_dir.join("tmp")).unwrap();

        let mut vfs = VirtualFileSystem::with_roots(Some(temp_dir.clone()), None);

        // Test mkdir
        let out = vfs.mkdir("-p /tmp/test_dir/sub");
        assert!(out.is_empty());
        assert!(temp_dir.join("tmp/test_dir/sub").is_dir());

        // Test write_file & cat
        let out = vfs.write_file("/tmp/test_dir/sub/payload.sh", "#!/bin/sh\necho pwned\n", false);
        assert!(out.is_empty());
        assert!(temp_dir.join("tmp/test_dir/sub/payload.sh").is_file());

        let cat_out = vfs.cat("/tmp/test_dir/sub/payload.sh");
        assert!(cat_out.contains("echo pwned"));

        // Test ls
        let ls_out = vfs.ls("-la /tmp/test_dir/sub");
        assert!(ls_out.contains("payload.sh"));

        // Test rm
        let rm_out = vfs.rm("-rf /tmp/test_dir");
        assert!(rm_out.is_empty());
        assert!(!temp_dir.join("tmp/test_dir").exists());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_vfs_root_listing() {
        let vfs = VirtualFileSystem::new();
        let out = vfs.ls("-la /");
        assert!(out.contains("bin"));
        assert!(out.contains("etc"));
        assert!(out.contains("home"));
        assert!(out.contains("proc"));
        assert!(out.contains("root"));
        assert!(out.contains("var"));
        assert!(out.contains("usr"));
    }
}
