rule rule_smb_scanner_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'smb-scanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smb-scanner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_smb_scanner_offensive_tool_keyword = "smbscan" nocase ascii wide
                        $string2_smb_scanner_offensive_tool_keyword = "smb-scanner" nocase ascii wide

    condition:
        any of them
}