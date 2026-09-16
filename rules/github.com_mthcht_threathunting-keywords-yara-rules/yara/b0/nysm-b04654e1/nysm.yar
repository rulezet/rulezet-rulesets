rule nysm
{
    meta:
        description = "Detection patterns for the tool 'nysm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nysm"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/nysm\/src\//
                        $string2 = "/nysm bash"
                        $string3 = "/nysm -dr socat TCP4-LISTEN"
                        $string4 = /\/nysm\s\-r\sssh\s.{0,1000}\@/
                        $string5 = /\/nysm\.bpf\.c/
                        $string6 = /\/nysm\.git/ nocase ascii wide
                        $string7 = /\/src\/nysm\.c/
                        $string8 = "eeriedusk/nysm" nocase ascii wide
                        $string9 = /nysm\.skel\.h/ nocase ascii wide
                        $string10 = /nysm\-master\.zip/ nocase ascii wide

    condition:
        any of them
}