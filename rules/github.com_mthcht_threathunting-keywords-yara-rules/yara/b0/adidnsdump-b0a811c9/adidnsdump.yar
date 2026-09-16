rule adidnsdump
{
    meta:
        description = "Detection patterns for the tool 'adidnsdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adidnsdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdnsdump\.py/ nocase ascii wide
                        $string2 = /\.py\s\-u\s.{0,1000}\s\?print\-zones\s/ nocase ascii wide
                        $string3 = /\/adidnsdump\.git/ nocase ascii wide
                        $string4 = /\/dnsdump\.py/
                        $string5 = /\\dnsdump\.py/ nocase ascii wide
                        $string6 = "adidnsdump" nocase ascii wide
                        $string7 = "dirkjanm/adidnsdump" nocase ascii wide

    condition:
        any of them
}