rule CSExec {
  meta:
    description   = "Detection patterns for the tool 'CSExec' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "CSExec"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1  = /\s\-\-blockDLLs\s\-\-ruy\-lopez/ nocase ascii wide
            $string2  = /\sCSExec\.py/ nocase ascii wide
            $string3  = /\s\-\-dll\s\-\-dllhijack\s/ nocase ascii wide
            $string4  = /\s\-\-donut\s\-\-rehash\sn\s\-\-silent\s\-o\s\/tmp\// nocase ascii wide
            $string5  = /\s\-m\svenv\scsexec\s/ nocase ascii wide
            $string6  = /\s\-\-no\-ppid\-spoof/ nocase ascii wide
            $string7  = /\s\-\-no\-sigthief/ nocase ascii wide
            $string8  = /\s\-pi\s\\\\\\\\\\\\\\\\\.\\\\\\\\pipe\\\\\\\\/ nocase ascii wide
            $string9  = /\s\-s\sputty\.exe_sig\s/ nocase ascii wide
            $string10 = /\s\-sc\sGetSyscallStub\s/ nocase ascii wide
            $string11 = /\s\-sc\sSysWhispers3/ nocase ascii wide
            $string12 = /\s\-\-shellcode\s.*\-\-dc\-ip\s/ nocase ascii wide
            $string13 = /\s\-\-shellcode\s.*\-\-silent/ nocase ascii wide
            $string14 = /\s\-\-shellcode\s\-\-remoteinject/ nocase ascii wide
            $string15 = /\s\-\-silent\s\-obf\sNixImports\s\-o\s\/tmp\// nocase ascii wide
            $string16 = /\s\-\-syscalls\sGetSyscallStub/ nocase ascii wide
            $string17 = /\s\-\-syscalls\sSysWhispers3/ nocase ascii wide
            $string18 = /\s\-\-syswhispers\s\-\-jump/ nocase ascii wide
            $string19 = /\/CSExec\.py/ nocase ascii wide
            $string20 = /\/CSExec\.py\.git/ nocase ascii wide
            $string21 = /~\/\.csexec/ nocase ascii wide
            $string22 = /Attempted\sto\sspawn\sa\ssocks\sproxy\sserver\sat\s0\.0\.0\.0:/ nocase ascii wide
            $string23 = /beacon_generate\.py/ nocase ascii wide
            $string24 = /bof_pack\.py\s/ nocase ascii wide
            $string25 = /csexec\/csexec_history/ nocase ascii wide
            $string26 = /dinjector\s\/i:.*\s\/p:/ nocase ascii wide
            $string27 = /dll_generator\.py/ nocase ascii wide
            $string28 = /keethief\-syscalls/ nocase ascii wide
            $string29 = /Metro\-Holografix\/CSExec/ nocase ascii wide
            $string30 = /nanodump_pipe/ nocase ascii wide
            $string31 = /nanodump\-pipes/ nocase ascii wide
            $string32 = /NimSyscallLoader\s\-/ nocase ascii wide
            $string33 = /\-\-noWAIT\s\-\-noFUNC\s\-\-donut\s\-\-rehash\sn\s\-\-silent\s\-o\s\/tmp\// nocase ascii wide
            $string34 = /pypykatz\slsa\sminidump\s/ nocase ascii wide
            $string35 = /reflective_assembly_minified\.ps1/ nocase ascii wide
            $string36 = /reverse_shell_minified\.js/ nocase ascii wide
            $string37 = /rlwrap\s\-cAr\snc\s\-lvnp\s/ nocase ascii wide
            $string38 = /secretsdump\s.*\-\-silent/ nocase ascii wide
            $string39 = /sharpsecretsdump/ nocase ascii wide
            $string40 = /SharpShot\.exe\s\// nocase ascii wide
            $string41 = /temp.*lsass_.*\.dmp/ nocase ascii wide
            $string42 = /templates.*CSExec\.cs/ nocase ascii wide
            $string43 = /templates.*HIPS_LIPS_processes\.txt/ nocase ascii wide
            $string44 = /templates.*reflective_assembly_minified\.ps1/ nocase ascii wide
            $string45 = /tmp.*lsass_.*\.dmp/ nocase ascii wide
            $string46 = /utils\/payloads\.db/ nocase ascii wide

  condition:
    any of them
}