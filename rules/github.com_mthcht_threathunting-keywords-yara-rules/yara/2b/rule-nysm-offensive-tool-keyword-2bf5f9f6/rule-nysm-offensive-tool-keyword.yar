rule rule_nysm_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nysm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nysm"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nysm_offensive_tool_keyword = /\.\/nysm\/src\//
                        $string2_nysm_offensive_tool_keyword = "/nysm bash"
                        $string3_nysm_offensive_tool_keyword = "/nysm -dr socat TCP4-LISTEN"
                        $string4_nysm_offensive_tool_keyword = /\/nysm\s\-r\sssh\s.{0,1000}\@/
                        $string5_nysm_offensive_tool_keyword = /\/nysm\.bpf\.c/
                        $string6_nysm_offensive_tool_keyword = /\/nysm\.git/ nocase ascii wide
                        $string7_nysm_offensive_tool_keyword = /\/src\/nysm\.c/
                        $string8_nysm_offensive_tool_keyword = "eeriedusk/nysm" nocase ascii wide
                        $string9_nysm_offensive_tool_keyword = /nysm\.skel\.h/ nocase ascii wide
                        $string10_nysm_offensive_tool_keyword = /nysm\-master\.zip/ nocase ascii wide

    condition:
        any of them
}