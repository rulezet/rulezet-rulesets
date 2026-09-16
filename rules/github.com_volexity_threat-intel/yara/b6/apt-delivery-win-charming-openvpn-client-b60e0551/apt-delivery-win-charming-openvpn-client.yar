rule apt_delivery_win_charming_openvpn_client: CharmingCypress
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-10-17"
        description = "Detects a fake OpenVPN client developed by CharmingCypress."
        hash1 = "2d99755d5cd25f857d6d3aa15631b69f570d20f95c6743574f3d3e3e8765f33c"
        os = "win"
        os_arch = "all"
        report = "TIB-20231027"
        scan_context = "file"
        severity = "critical"
        last_modified = "2023-10-27T16:17:32Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9768
        version = 2

    strings:
        $s1 = "DONE!"
        $s2 = "AppCore.dll"
        $s3 = "ultralight@@"

    condition:
        all of ($s*)
}