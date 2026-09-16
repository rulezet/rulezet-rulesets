rule Freeze
{
    meta:
        description = "Detection patterns for the tool 'Freeze' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Freeze"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-encrypt\s.{0,1000}\s\-process\s.{0,1000}\s\-sandbox\s/ nocase ascii wide
                        $string2 = "/optiv/Freeze/" nocase ascii wide
                        $string3 = /\\freeze\.go/ nocase ascii wide
                        $string4 = /build\sFreeze\.go/ nocase ascii wide
                        $string5 = /Freeze_.{0,1000}_darwin_amd64/
                        $string6 = /Freeze_.{0,1000}_linux_amd64/

    condition:
        any of them
}