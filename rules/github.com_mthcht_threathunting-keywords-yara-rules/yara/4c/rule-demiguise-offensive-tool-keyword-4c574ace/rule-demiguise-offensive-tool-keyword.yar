rule rule_demiguise_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'demiguise' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "demiguise"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_demiguise_offensive_tool_keyword = /\sdemiguise\.py/ nocase ascii wide
                        $string2_demiguise_offensive_tool_keyword = /\s\-k\s.{0,1000}\s\-c\s.{0,1000}\.exe.{0,1000}\s\-p\sOutlook\.Application\s\-o\s.{0,1000}\.hta/ nocase ascii wide
                        $string3_demiguise_offensive_tool_keyword = /\s\-k\s.{0,1000}\s\-c\s.{0,1000}cmd\.exe\s\/c\s.{0,1000}\s\-o\s.{0,1000}\.hta\s\-p\sShellBrowserWindow/ nocase ascii wide
                        $string4_demiguise_offensive_tool_keyword = /\/demiguise\.py/ nocase ascii wide
                        $string5_demiguise_offensive_tool_keyword = /\\demiguise\.py/ nocase ascii wide
                        $string6_demiguise_offensive_tool_keyword = "nccgroup/demiguise" nocase ascii wide
                        $string7_demiguise_offensive_tool_keyword = /Yh0Js82rIfFEbS6pR7oUkN0Use54pIZBa3fpYprAMuURNrZZGc6cM8dc\+AC/ nocase ascii wide

    condition:
        any of them
}