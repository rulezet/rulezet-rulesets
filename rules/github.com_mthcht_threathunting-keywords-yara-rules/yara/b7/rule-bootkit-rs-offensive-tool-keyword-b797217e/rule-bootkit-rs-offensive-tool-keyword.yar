rule rule_bootkit_rs_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bootkit-rs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bootkit-rs"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_bootkit_rs_offensive_tool_keyword = "/bootkit-rs" nocase ascii wide
                        $string2_bootkit_rs_offensive_tool_keyword = /\\bootkit\-rs/ nocase ascii wide
                        $string3_bootkit_rs_offensive_tool_keyword = /bootkit\-rs\.git/ nocase ascii wide
                        $string4_bootkit_rs_offensive_tool_keyword = "bootkit-rs-master" nocase ascii wide
                        $string5_bootkit_rs_offensive_tool_keyword = "master/bootkit/src" nocase ascii wide
                        $string6_bootkit_rs_offensive_tool_keyword = /redlotus\.efi/ nocase ascii wide
                        $string7_bootkit_rs_offensive_tool_keyword = "x86_64-unknown-uefi" nocase ascii wide

    condition:
        any of them
}