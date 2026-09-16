rule krbjack
{
    meta:
        description = "Detection patterns for the tool 'krbjack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "krbjack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " install krbjack" nocase ascii wide
                        $string2 = " KRB hijacking module " nocase ascii wide
                        $string3 = /\s\-\-target\-name\s.{0,1000}\s\-\-domain\s.{0,1000}\s\-\-dc\-ip\s.{0,1000}\s\-\-executable\s.{0,1000}\.exe/ nocase ascii wide
                        $string4 = /\/krbjack\.git/ nocase ascii wide
                        $string5 = "almandin/krbjack" nocase ascii wide
                        $string6 = "krbjack -" nocase ascii wide
                        $string7 = /krbjack\.tcpforward/ nocase ascii wide
                        $string8 = /krbjacker\.py/ nocase ascii wide
                        $string9 = "krbjack-main" nocase ascii wide

    condition:
        any of them
}