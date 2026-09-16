rule rule_evilqr_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'evilqr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evilqr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_evilqr_offensive_tool_keyword = /\/evilqr\.git/ nocase ascii wide
                        $string2_evilqr_offensive_tool_keyword = "evilqr-main" nocase ascii wide
                        $string3_evilqr_offensive_tool_keyword = "evilqr-phishing" nocase ascii wide
                        $string4_evilqr_offensive_tool_keyword = "evilqr-server" nocase ascii wide
                        $string5_evilqr_offensive_tool_keyword = /http\:\/\/127\.0\.0\.1\:35000/ nocase ascii wide
                        $string6_evilqr_offensive_tool_keyword = "kgretzky/evilqr" nocase ascii wide

    condition:
        any of them
}