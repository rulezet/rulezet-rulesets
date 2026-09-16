rule impersonate_rs
{
    meta:
        description = "Detection patterns for the tool 'impersonate-rs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "impersonate-rs"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sexec\s.{0,1000}\s\-p\s.{0,1000}\s\-c\s/ nocase ascii wide
                        $string2 = /\sexec\s.{0,1000}\s\-\-pid\s.{0,1000}\s\-\-command\s/ nocase ascii wide
                        $string3 = "/impersonate-rs" nocase ascii wide
                        $string4 = /\/irs\.exe/ nocase ascii wide
                        $string5 = /\\irs\.exe/ nocase ascii wide
                        $string6 = /irs\.exe\s\-/ nocase ascii wide
                        $string7 = /irs\.exe\sexec/ nocase ascii wide
                        $string8 = /irs\.exe\slist/ nocase ascii wide
                        $string9 = /irs\.exe\slist/ nocase ascii wide

    condition:
        any of them
}