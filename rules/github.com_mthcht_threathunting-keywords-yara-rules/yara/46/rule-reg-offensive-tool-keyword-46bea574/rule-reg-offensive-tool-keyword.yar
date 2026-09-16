rule rule_reg_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'reg' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reg"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_reg_offensive_tool_keyword = /reg\sdelete\s.{0,1000}HKEY_LOCAL_MACHINE\\SOFTWARE\\YourSoftware\\Schedule\\TaskCache\\Tree\\.{0,1000}\sSD\s/ nocase ascii wide
                        $string2_reg_offensive_tool_keyword = /reg\sdelete\sHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\s\/va\s\/f/ nocase ascii wide

    condition:
        any of them
}