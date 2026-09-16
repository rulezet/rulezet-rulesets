rule pslist
{
    meta:
        description = "Detection patterns for the tool 'pslist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pslist"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/pslist\.exe/ nocase ascii wide
                        $string2 = /\/pslist64\.exe/ nocase ascii wide
                        $string3 = /\\pslist\.exe/ nocase ascii wide
                        $string4 = /\\pslist64\.exe/ nocase ascii wide
                        $string5 = ">Sysinternals PsList<" nocase ascii wide
                        $string6 = "d3247f03dcd7b9335344ebba76a0b92370f32f1cb0e480c734da52db2bd8df60" nocase ascii wide

    condition:
        any of them
}