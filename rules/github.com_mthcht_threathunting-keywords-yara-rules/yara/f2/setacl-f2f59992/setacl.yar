rule SetACL
{
    meta:
        description = "Detection patterns for the tool 'SetACL' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SetACL"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/SetACL\.exe/ nocase ascii wide
                        $string2 = /\/SetACL64\.\.exe/ nocase ascii wide
                        $string3 = /\\SetACL\.exe/ nocase ascii wide
                        $string4 = /\\SetACL64\.exe/ nocase ascii wide
                        $string5 = /\>SetACL\.exe\</ nocase ascii wide
                        $string6 = /\>SetACL64\.\.exe\</ nocase ascii wide

    condition:
        any of them
}