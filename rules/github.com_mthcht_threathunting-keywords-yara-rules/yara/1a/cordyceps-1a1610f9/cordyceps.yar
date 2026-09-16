rule Cordyceps
{
    meta:
        description = "Detection patterns for the tool 'Cordyceps' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cordyceps"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Cordyceps\.git/ nocase ascii wide
                        $string2 = /cordyceps\.exe/ nocase ascii wide
                        $string3 = /Cordyceps\-main\.zip/ nocase ascii wide
                        $string4 = /nasm\s\-f\swin64\s\.\/syscalls\.asm\s\-o\s\.\/syscalls\.obj/
                        $string5 = "pard0p/Cordyceps" nocase ascii wide

    condition:
        any of them
}