rule rule_wiresocks_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wiresocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wiresocks"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wiresocks_offensive_tool_keyword = /\sredsocks\.sh/ nocase ascii wide
                        $string2_wiresocks_offensive_tool_keyword = /\/redsocks\.sh/
                        $string3_wiresocks_offensive_tool_keyword = /\/redsocks\-fw\.sh/
                        $string4_wiresocks_offensive_tool_keyword = /\/wiresocks\.git/ nocase ascii wide
                        $string5_wiresocks_offensive_tool_keyword = /\-c\s\/tmp\/redsocks\.conf/ nocase ascii wide
                        $string6_wiresocks_offensive_tool_keyword = "docker-compose logs wiresocks" nocase ascii wide
                        $string7_wiresocks_offensive_tool_keyword = "iptables -t nat -A REDSOCKS" nocase ascii wide
                        $string8_wiresocks_offensive_tool_keyword = /redsocks\-fw\.sh\sstop/
                        $string9_wiresocks_offensive_tool_keyword = "sensepost/wiresocks" nocase ascii wide
                        $string10_wiresocks_offensive_tool_keyword = "wiresocks-main" nocase ascii wide
                        $string11_wiresocks_offensive_tool_keyword = "wiresocks-redsocks" nocase ascii wide

    condition:
        any of them
}