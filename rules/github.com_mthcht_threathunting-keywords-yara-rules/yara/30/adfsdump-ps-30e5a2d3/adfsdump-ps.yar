rule ADFSDump_PS
{
    meta:
        description = "Detection patterns for the tool 'ADFSDump-PS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADFSDump-PS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/ADFSDump\-PS\.git/ nocase ascii wide
                        $string2 = /\\ADFSDump\-PS\-main/ nocase ascii wide
                        $string3 = /\\Golden\.ps1/ nocase ascii wide
                        $string4 = "c04b117bc1e5883c3c85ab2823071b33dbf1344e581e250fa5d80a8fae6b338b" nocase ascii wide
                        $string5 = "ZephrFish/ADFSDump-PS" nocase ascii wide

    condition:
        any of them
}