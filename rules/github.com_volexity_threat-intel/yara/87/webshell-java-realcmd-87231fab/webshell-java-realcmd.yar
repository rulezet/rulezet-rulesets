rule webshell_java_realcmd
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the RealCMD webshell, one of the payloads for BEHINDER."
        date = "2022-06-01"
        hash1 = "a9a30455d6f3a0a8cd0274ae954aa41674b6fd52877fafc84a9cb833fd8858f6"
        os = "all"
        os_arch = "all"
        reference = "https://github.com/Freakboy/Behinder/blob/master/src/main/java/vip/youwe/sheller/payload/java/RealCMD.java"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-07-30T08:32:55Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6786
        version = 4

    strings:
        $fn1 = "runCmd" wide ascii fullword
        $fn2 = "RealCMD" ascii wide fullword
        $fn3 = "buildJson" ascii wide fullword
    condition:
        all of ($fn*)
}