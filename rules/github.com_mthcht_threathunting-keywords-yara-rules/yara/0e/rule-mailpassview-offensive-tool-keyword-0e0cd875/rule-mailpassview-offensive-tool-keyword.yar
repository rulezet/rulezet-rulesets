rule rule_MailPassView_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MailPassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MailPassView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MailPassView_offensive_tool_keyword = /\/mailpv\.exe/ nocase ascii wide
                        $string2_MailPassView_offensive_tool_keyword = /\/utils\/mailpv\.html/ nocase ascii wide
                        $string3_MailPassView_offensive_tool_keyword = /\\mailpv\.exe/ nocase ascii wide
                        $string4_MailPassView_offensive_tool_keyword = "18e9b39ab7c27ea80c6b76fc04881a5348de491ab22abe65a6bdb7254e23d5d1" nocase ascii wide
                        $string5_MailPassView_offensive_tool_keyword = "5be325905df8aab7089ab2348d89343f55a2f88dadd75de8f382e8fa026451bd" nocase ascii wide
                        $string6_MailPassView_offensive_tool_keyword = "5be325905df8aab7089ab2348d89343f55a2f88dadd75de8f382e8fa026451bd" nocase ascii wide
                        $string7_MailPassView_offensive_tool_keyword = "Email  Password-Recovery" nocase ascii wide

    condition:
        any of them
}