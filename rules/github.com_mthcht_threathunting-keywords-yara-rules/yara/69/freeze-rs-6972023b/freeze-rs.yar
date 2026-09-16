rule Freeze_rs
{
    meta:
        description = "Detection patterns for the tool 'Freeze.rs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Freeze.rs"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sFreeze\.rs\// nocase ascii wide
                        $string2 = /\/Freeze\.rs/ nocase ascii wide
                        $string3 = "Freeze-rs -" nocase ascii wide
                        $string4 = /Freeze\-rs\.exe/ nocase ascii wide
                        $string5 = "Freeze-rs_darwin_amd64"
                        $string6 = "Freeze-rs_linux_amd64"
                        $string7 = /Freeze\-rs_windows_amd64\.exe/ nocase ascii wide

    condition:
        any of them
}