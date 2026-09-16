rule rule_reGeorg_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'reGeorg' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reGeorg"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_reGeorg_offensive_tool_keyword = /\.\.\.\severy\soffice\sneeds\sa\stool\slike\sGeorg/ nocase ascii wide
                        $string2_reGeorg_offensive_tool_keyword = /\/reGeorg\.git/ nocase ascii wide
                        $string3_reGeorg_offensive_tool_keyword = /\/tunnel\.nosocket\.php/ nocase ascii wide
                        $string4_reGeorg_offensive_tool_keyword = /\/tunnel\.tomcat\.5\.jsp/ nocase ascii wide
                        $string5_reGeorg_offensive_tool_keyword = "Georg is not ready, please check url" nocase ascii wide
                        $string6_reGeorg_offensive_tool_keyword = "Georg says, 'All seems fine'" nocase ascii wide
                        $string7_reGeorg_offensive_tool_keyword = "reGeorg-master" nocase ascii wide
                        $string8_reGeorg_offensive_tool_keyword = /reGeorgSocksProxy\.py/ nocase ascii wide
                        $string9_reGeorg_offensive_tool_keyword = "sensepost/reGeorg" nocase ascii wide
                        $string10_reGeorg_offensive_tool_keyword = /Socks\sserver\sfor\sreGeorg\sHTTP\(s\)\stunneller/ nocase ascii wide
                        $string11_reGeorg_offensive_tool_keyword = /Starting\ssocks\sserver\s.{0,1000}\stunnel\sat\s/ nocase ascii wide

    condition:
        any of them
}