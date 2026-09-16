rule megatools
{
    meta:
        description = "Detection patterns for the tool 'megatools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "megatools"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/megatools\.exe/ nocase ascii wide
                        $string2 = /\\\.megatools\.cache/ nocase ascii wide
                        $string3 = /\\megatools\-.{0,1000}\-win64\\/ nocase ascii wide
                        $string4 = /\\megatools\.exe/ nocase ascii wide
                        $string5 = /\\Users\\.{0,1000}\\AppData\\Local\\Temp\\.{0,1000}\.megatools\.cache/ nocase ascii wide
                        $string6 = /megatools\scopy\s\-l\s.{0,1000}\s\-r\s/ nocase ascii wide
                        $string7 = "megatools put " nocase ascii wide

    condition:
        any of them
}