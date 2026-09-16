rule msfvenom
{
    meta:
        description = "Detection patterns for the tool 'msfvenom' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "msfvenom"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " windows/shell/bind_tcp " nocase ascii wide
                        $string2 = "/msfvenom/" nocase ascii wide
                        $string3 = /exec\sCMD\=\/bin\/sh\s\-f\self\s\-o\s.{0,1000}\.elf/
                        $string4 = "msfencode" nocase ascii wide
                        $string5 = "msfpayload" nocase ascii wide
                        $string6 = "msfvenom -" nocase ascii wide

    condition:
        any of them
}