rule rule_takeown_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'takeown' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "takeown"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_takeown_greyware_tool_keyword = /takeown\s\/f\s\\"C\:\\windows\\system32\\config\\SAM\\"/ nocase ascii wide
                        $string2_takeown_greyware_tool_keyword = /takeown\s\/f\sC\:\\Windows\\System32\\amsi\.dll\s\/a/ nocase ascii wide
                        $string3_takeown_greyware_tool_keyword = /takeown\s\/f\sc\:\\windows\\system32\\sethc\.exe/ nocase ascii wide
                        $string4_takeown_greyware_tool_keyword = /takeown\s\/f\sc\:\\windows\\system32\\sethcold\.exe/ nocase ascii wide

    condition:
        any of them
}