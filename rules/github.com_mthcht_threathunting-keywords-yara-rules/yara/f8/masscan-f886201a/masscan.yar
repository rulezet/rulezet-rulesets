rule masscan
{
    meta:
        description = "Detection patterns for the tool 'masscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "masscan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sinstall\s.{0,1000}masscan/
                        $string2 = /\\masscan\\src\\/ nocase ascii wide
                        $string3 = "bin/masscan"
                        $string4 = "C88D7583-254F-4BE6-A9B9-89A5BB52E679"
                        $string5 = "ivre-masscan/"
                        $string6 = "masscan -c "
                        $string7 = "masscan --nmap"
                        $string8 = "masscan -p"
                        $string9 = /masscan.{0,1000}\s\-p/
                        $string10 = /masscan\.exe\s/ nocase ascii wide
                        $string11 = "robertdavidgraham/masscan" nocase ascii wide
                        $string12 = /unix\/1\.0\sUPnP\/1\.1\smasscan\// nocase ascii wide
                        $string13 = "xterm -e masscan" nocase ascii wide
                        $string14 = "masscan "

    condition:
        any of them
}