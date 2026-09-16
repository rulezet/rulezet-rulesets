rule rule_msfvenom_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'msfvenom' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "msfvenom"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_msfvenom_offensive_tool_keyword = " windows/shell/bind_tcp " nocase ascii wide
                        $string2_msfvenom_offensive_tool_keyword = "/msfvenom/" nocase ascii wide
                        $string3_msfvenom_offensive_tool_keyword = /exec\sCMD\=\/bin\/sh\s\-f\self\s\-o\s.{0,1000}\.elf/
                        $string4_msfvenom_offensive_tool_keyword = "msfencode" nocase ascii wide
                        $string5_msfvenom_offensive_tool_keyword = "msfpayload" nocase ascii wide
                        $string6_msfvenom_offensive_tool_keyword = "msfvenom -" nocase ascii wide

    condition:
        any of them
}