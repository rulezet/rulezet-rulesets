rule netstat
{
    meta:
        description = "Detection patterns for the tool 'netstat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netstat"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "netsat -naop" nocase ascii wide
                        $string2 = "netstat -ano" nocase ascii wide
                        $string3 = "netstat -ant" nocase ascii wide
                        $string4 = /NETSTAT\.EXE.{0,1000}\s\-ano/ nocase ascii wide

    condition:
        any of them
}