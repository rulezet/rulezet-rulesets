rule rule_GIUDA_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GIUDA' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GIUDA"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GIUDA_offensive_tool_keyword = " -runaslsass" nocase ascii wide
                        $string2_GIUDA_offensive_tool_keyword = /\.exe\s\-gettgs\s\-luid\:/ nocase ascii wide
                        $string3_GIUDA_offensive_tool_keyword = /\.exe\s\-ptt\sticket\:.{0,1000}\.kirbi/ nocase ascii wide
                        $string4_GIUDA_offensive_tool_keyword = /GIUDA.{0,1000}\s\-askluids/ nocase ascii wide
                        $string5_GIUDA_offensive_tool_keyword = /GIUDA\-main\.zip/ nocase ascii wide
                        $string6_GIUDA_offensive_tool_keyword = /guida\.exe\s\-/ nocase ascii wide

    condition:
        any of them
}