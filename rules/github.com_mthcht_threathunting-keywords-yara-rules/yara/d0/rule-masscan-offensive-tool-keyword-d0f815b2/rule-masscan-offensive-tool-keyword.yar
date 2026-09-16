rule rule_masscan_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'masscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "masscan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_masscan_offensive_tool_keyword = /\sinstall\s.{0,1000}masscan/
                        $string2_masscan_offensive_tool_keyword = /\\masscan\\src\\/ nocase ascii wide
                        $string3_masscan_offensive_tool_keyword = "bin/masscan"
                        $string4_masscan_offensive_tool_keyword = "C88D7583-254F-4BE6-A9B9-89A5BB52E679"
                        $string5_masscan_offensive_tool_keyword = "ivre-masscan/"
                        $string6_masscan_offensive_tool_keyword = "masscan -c "
                        $string7_masscan_offensive_tool_keyword = "masscan --nmap"
                        $string8_masscan_offensive_tool_keyword = "masscan -p"
                        $string9_masscan_offensive_tool_keyword = /masscan.{0,1000}\s\-p/
                        $string10_masscan_offensive_tool_keyword = /masscan\.exe\s/ nocase ascii wide
                        $string11_masscan_offensive_tool_keyword = "robertdavidgraham/masscan" nocase ascii wide
                        $string12_masscan_offensive_tool_keyword = /unix\/1\.0\sUPnP\/1\.1\smasscan\// nocase ascii wide
                        $string13_masscan_offensive_tool_keyword = "xterm -e masscan" nocase ascii wide
                        $string14_masscan_offensive_tool_keyword = "masscan "

    condition:
        any of them
}