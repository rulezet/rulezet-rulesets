rule rule_impersonate_rs_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'impersonate-rs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "impersonate-rs"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_impersonate_rs_offensive_tool_keyword = /\sexec\s.{0,1000}\s\-p\s.{0,1000}\s\-c\s/ nocase ascii wide
                        $string2_impersonate_rs_offensive_tool_keyword = /\sexec\s.{0,1000}\s\-\-pid\s.{0,1000}\s\-\-command\s/ nocase ascii wide
                        $string3_impersonate_rs_offensive_tool_keyword = "/impersonate-rs" nocase ascii wide
                        $string4_impersonate_rs_offensive_tool_keyword = /\/irs\.exe/ nocase ascii wide
                        $string5_impersonate_rs_offensive_tool_keyword = /\\irs\.exe/ nocase ascii wide
                        $string6_impersonate_rs_offensive_tool_keyword = /irs\.exe\s\-/ nocase ascii wide
                        $string7_impersonate_rs_offensive_tool_keyword = /irs\.exe\sexec/ nocase ascii wide
                        $string8_impersonate_rs_offensive_tool_keyword = /irs\.exe\slist/ nocase ascii wide
                        $string9_impersonate_rs_offensive_tool_keyword = /irs\.exe\slist/ nocase ascii wide

    condition:
        any of them
}