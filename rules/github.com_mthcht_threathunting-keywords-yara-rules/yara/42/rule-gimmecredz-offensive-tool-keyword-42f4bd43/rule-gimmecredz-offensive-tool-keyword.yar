rule rule_gimmecredz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gimmecredz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gimmecredz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gimmecredz_offensive_tool_keyword = "dump_chrome_user" nocase ascii wide
                        $string2_gimmecredz_offensive_tool_keyword = "dump_firefox_user" nocase ascii wide
                        $string3_gimmecredz_offensive_tool_keyword = "dump_jenkins" nocase ascii wide
                        $string4_gimmecredz_offensive_tool_keyword = "dump_keepassx" nocase ascii wide
                        $string5_gimmecredz_offensive_tool_keyword = "dump_ssh_keys" nocase ascii wide
                        $string6_gimmecredz_offensive_tool_keyword = "dump_tomcat" nocase ascii wide
                        $string7_gimmecredz_offensive_tool_keyword = "dump_webconf" nocase ascii wide
                        $string8_gimmecredz_offensive_tool_keyword = "dump_webpass" nocase ascii wide
                        $string9_gimmecredz_offensive_tool_keyword = "dump_wifi_wpa_" nocase ascii wide
                        $string10_gimmecredz_offensive_tool_keyword = "gimmecredz" nocase ascii wide

    condition:
        any of them
}