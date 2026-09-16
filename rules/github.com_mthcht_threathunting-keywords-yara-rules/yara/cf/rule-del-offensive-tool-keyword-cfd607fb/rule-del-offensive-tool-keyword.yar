rule rule_del_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'del' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "del"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_del_offensive_tool_keyword = /del\s\/F\s\/Q\s\%APPDATA\%\\Microsoft\\Windows\\Recent\\/ nocase ascii wide
                        $string2_del_offensive_tool_keyword = /del\s\/F\s\/Q\s\%APPDATA\%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\/ nocase ascii wide
                        $string3_del_offensive_tool_keyword = /del\s\/F\s\/Q\s\%APPDATA\%\\Microsoft\\Windows\\Recent\\CustomDestinations\\/ nocase ascii wide
                        $string4_del_offensive_tool_keyword = /del\s\/F\s\/Q\sC\:\\\\Windows\\\\Prefetch\\\\/ nocase ascii wide
                        $string5_del_offensive_tool_keyword = /del\s\/F\s\/Q\sC\:\\Windows\\Prefetch\\/ nocase ascii wide
                        $string6_del_offensive_tool_keyword = /del\sC\:\\Windows\\AppCompat\\Programs\\RecentFileCache\.bcf/ nocase ascii wide

    condition:
        any of them
}