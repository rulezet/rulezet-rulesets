rule GIUDA
{
    meta:
        description = "Detection patterns for the tool 'GIUDA' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GIUDA"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -runaslsass" nocase ascii wide
                        $string2 = /\.exe\s\-gettgs\s\-luid\:/ nocase ascii wide
                        $string3 = /\.exe\s\-ptt\sticket\:.{0,1000}\.kirbi/ nocase ascii wide
                        $string4 = /GIUDA.{0,1000}\s\-askluids/ nocase ascii wide
                        $string5 = /GIUDA\-main\.zip/ nocase ascii wide
                        $string6 = /guida\.exe\s\-/ nocase ascii wide

    condition:
        any of them
}