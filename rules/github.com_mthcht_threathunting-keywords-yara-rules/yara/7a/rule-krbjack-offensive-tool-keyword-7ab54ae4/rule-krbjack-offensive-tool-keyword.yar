rule rule_krbjack_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'krbjack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "krbjack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_krbjack_offensive_tool_keyword = " install krbjack" nocase ascii wide
                        $string2_krbjack_offensive_tool_keyword = " KRB hijacking module " nocase ascii wide
                        $string3_krbjack_offensive_tool_keyword = /\s\-\-target\-name\s.{0,1000}\s\-\-domain\s.{0,1000}\s\-\-dc\-ip\s.{0,1000}\s\-\-executable\s.{0,1000}\.exe/ nocase ascii wide
                        $string4_krbjack_offensive_tool_keyword = /\/krbjack\.git/ nocase ascii wide
                        $string5_krbjack_offensive_tool_keyword = "almandin/krbjack" nocase ascii wide
                        $string6_krbjack_offensive_tool_keyword = "krbjack -" nocase ascii wide
                        $string7_krbjack_offensive_tool_keyword = /krbjack\.tcpforward/ nocase ascii wide
                        $string8_krbjack_offensive_tool_keyword = /krbjacker\.py/ nocase ascii wide
                        $string9_krbjack_offensive_tool_keyword = "krbjack-main" nocase ascii wide

    condition:
        any of them
}