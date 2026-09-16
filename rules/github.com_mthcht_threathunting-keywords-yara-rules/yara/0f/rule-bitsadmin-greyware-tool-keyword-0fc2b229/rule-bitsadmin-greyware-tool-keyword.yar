rule rule_bitsadmin_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bitsadmin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bitsadmin"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_bitsadmin_greyware_tool_keyword = /b\^i\^t\^s\^a\^d\^min\^\s\/t\^ra\^n\^s\^f\^e\^r\^\s\^\/\^d\^o\^w\^n\^l\^o\^a\^d/ nocase ascii wide
                        $string2_bitsadmin_greyware_tool_keyword = "bitsadmin /transfer " nocase ascii wide
                        $string3_bitsadmin_greyware_tool_keyword = /bitsadmin\s\/transfer\sdebjob\s\/download\s\/priority\snormal\s\\.{0,1000}\\C\$\\Windows\\.{0,1000}\.dll/ nocase ascii wide

    condition:
        any of them
}