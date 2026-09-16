rule rule_Freeze_rs_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Freeze.rs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Freeze.rs"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Freeze_rs_offensive_tool_keyword = /\sFreeze\.rs\// nocase ascii wide
                        $string2_Freeze_rs_offensive_tool_keyword = /\/Freeze\.rs/ nocase ascii wide
                        $string3_Freeze_rs_offensive_tool_keyword = "Freeze-rs -" nocase ascii wide
                        $string4_Freeze_rs_offensive_tool_keyword = /Freeze\-rs\.exe/ nocase ascii wide
                        $string5_Freeze_rs_offensive_tool_keyword = "Freeze-rs_darwin_amd64"
                        $string6_Freeze_rs_offensive_tool_keyword = "Freeze-rs_linux_amd64"
                        $string7_Freeze_rs_offensive_tool_keyword = /Freeze\-rs_windows_amd64\.exe/ nocase ascii wide

    condition:
        any of them
}