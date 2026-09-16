rule bootkit_rs
{
    meta:
        description = "Detection patterns for the tool 'bootkit-rs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bootkit-rs"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/bootkit-rs" nocase ascii wide
                        $string2 = /\\bootkit\-rs/ nocase ascii wide
                        $string3 = /bootkit\-rs\.git/ nocase ascii wide
                        $string4 = "bootkit-rs-master" nocase ascii wide
                        $string5 = "master/bootkit/src" nocase ascii wide
                        $string6 = /redlotus\.efi/ nocase ascii wide
                        $string7 = "x86_64-unknown-uefi" nocase ascii wide

    condition:
        any of them
}