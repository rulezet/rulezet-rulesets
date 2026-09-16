rule Huan
{
    meta:
        description = "Detection patterns for the tool 'Huan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Huan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/huan\.exe\s/ nocase ascii wide
                        $string2 = "/HuanLoader/" nocase ascii wide
                        $string3 = /\\huan\.exe\s/ nocase ascii wide
                        $string4 = /huan\.exe\s.{0,1000}\.exe/ nocase ascii wide
                        $string5 = /Huan\.sln/ nocase ascii wide
                        $string6 = /Huan\.vcxproj/ nocase ascii wide
                        $string7 = /HuanLoader\.vcxproj/ nocase ascii wide

    condition:
        any of them
}