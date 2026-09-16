rule gimmecredz
{
    meta:
        description = "Detection patterns for the tool 'gimmecredz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gimmecredz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "dump_chrome_user" nocase ascii wide
                        $string2 = "dump_firefox_user" nocase ascii wide
                        $string3 = "dump_jenkins" nocase ascii wide
                        $string4 = "dump_keepassx" nocase ascii wide
                        $string5 = "dump_ssh_keys" nocase ascii wide
                        $string6 = "dump_tomcat" nocase ascii wide
                        $string7 = "dump_webconf" nocase ascii wide
                        $string8 = "dump_webpass" nocase ascii wide
                        $string9 = "dump_wifi_wpa_" nocase ascii wide
                        $string10 = "gimmecredz" nocase ascii wide

    condition:
        any of them
}