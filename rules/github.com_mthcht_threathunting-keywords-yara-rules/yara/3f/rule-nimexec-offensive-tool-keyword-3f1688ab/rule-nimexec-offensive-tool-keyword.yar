rule rule_NimExec_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NimExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NimExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NimExec_offensive_tool_keyword = /\/NimExec\.git/ nocase ascii wide
                        $string2_NimExec_offensive_tool_keyword = "123abcbde966780cef8d9ec24523acac" nocase ascii wide
                        $string3_NimExec_offensive_tool_keyword = /cmd\.exe\s\/c\s.{0,1000}echo\stest\s\>\sC\:\\Users\\Public\\test\.txt/ nocase ascii wide
                        $string4_NimExec_offensive_tool_keyword = "frkngksl/NimExec" nocase ascii wide
                        $string5_NimExec_offensive_tool_keyword = /NimExec\.exe/ nocase ascii wide
                        $string6_NimExec_offensive_tool_keyword = "NimExec-master" nocase ascii wide

    condition:
        any of them
}