rule wiresocks
{
    meta:
        description = "Detection patterns for the tool 'wiresocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wiresocks"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sredsocks\.sh/ nocase ascii wide
                        $string2 = /\/redsocks\.sh/
                        $string3 = /\/redsocks\-fw\.sh/
                        $string4 = /\/wiresocks\.git/ nocase ascii wide
                        $string5 = /\-c\s\/tmp\/redsocks\.conf/ nocase ascii wide
                        $string6 = "docker-compose logs wiresocks" nocase ascii wide
                        $string7 = "iptables -t nat -A REDSOCKS" nocase ascii wide
                        $string8 = /redsocks\-fw\.sh\sstop/
                        $string9 = "sensepost/wiresocks" nocase ascii wide
                        $string10 = "wiresocks-main" nocase ascii wide
                        $string11 = "wiresocks-redsocks" nocase ascii wide

    condition:
        any of them
}