rule NimExec
{
    meta:
        description = "Detection patterns for the tool 'NimExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NimExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/NimExec\.git/ nocase ascii wide
                        $string2 = "123abcbde966780cef8d9ec24523acac" nocase ascii wide
                        $string3 = /cmd\.exe\s\/c\s.{0,1000}echo\stest\s\>\sC\:\\Users\\Public\\test\.txt/ nocase ascii wide
                        $string4 = "frkngksl/NimExec" nocase ascii wide
                        $string5 = /NimExec\.exe/ nocase ascii wide
                        $string6 = "NimExec-master" nocase ascii wide

    condition:
        any of them
}