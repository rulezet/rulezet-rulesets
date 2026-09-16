rule apt_delivery_lnk_charmingcypress_dec23: CharmingCypress
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-01-04"
        description = "Detects an LNK format used by CharmingCypress in attacks in December 2023."
        hash1 = "f6f0f682668f78dbecfc30a0e0c76b6a3d86298869fb44b39adf19fdcdca5762"
        os = "win"
        os_arch = "all"
        report = "TIB-20240111"
        scan_context = "file"
        severity = "critical"
        last_modified = "2025-07-18T16:14:51Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10040
        version = 4

    strings:
        $s1 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe"  wide
        $s2 = "..\\..\\..\\..\\Windows\\System32\\cmd.exe" wide
        $s3 = "/c set" wide
        $s4 = "& call %" wide

        $desktop = "desktop-b24ekvp" ascii

    condition:
        uint32be(0) == 0x4C000000 and
        (
            all of ($s*) or
            $desktop
        )
}