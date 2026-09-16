rule demiguise
{
    meta:
        description = "Detection patterns for the tool 'demiguise' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "demiguise"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdemiguise\.py/ nocase ascii wide
                        $string2 = /\s\-k\s.{0,1000}\s\-c\s.{0,1000}\.exe.{0,1000}\s\-p\sOutlook\.Application\s\-o\s.{0,1000}\.hta/ nocase ascii wide
                        $string3 = /\s\-k\s.{0,1000}\s\-c\s.{0,1000}cmd\.exe\s\/c\s.{0,1000}\s\-o\s.{0,1000}\.hta\s\-p\sShellBrowserWindow/ nocase ascii wide
                        $string4 = /\/demiguise\.py/ nocase ascii wide
                        $string5 = /\\demiguise\.py/ nocase ascii wide
                        $string6 = "nccgroup/demiguise" nocase ascii wide
                        $string7 = /Yh0Js82rIfFEbS6pR7oUkN0Use54pIZBa3fpYprAMuURNrZZGc6cM8dc\+AC/ nocase ascii wide

    condition:
        any of them
}