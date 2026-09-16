rule reGeorg
{
    meta:
        description = "Detection patterns for the tool 'reGeorg' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reGeorg"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\.\.\severy\soffice\sneeds\sa\stool\slike\sGeorg/ nocase ascii wide
                        $string2 = /\/reGeorg\.git/ nocase ascii wide
                        $string3 = /\/tunnel\.nosocket\.php/ nocase ascii wide
                        $string4 = /\/tunnel\.tomcat\.5\.jsp/ nocase ascii wide
                        $string5 = "Georg is not ready, please check url" nocase ascii wide
                        $string6 = "Georg says, 'All seems fine'" nocase ascii wide
                        $string7 = "reGeorg-master" nocase ascii wide
                        $string8 = /reGeorgSocksProxy\.py/ nocase ascii wide
                        $string9 = "sensepost/reGeorg" nocase ascii wide
                        $string10 = /Socks\sserver\sfor\sreGeorg\sHTTP\(s\)\stunneller/ nocase ascii wide
                        $string11 = /Starting\ssocks\sserver\s.{0,1000}\stunnel\sat\s/ nocase ascii wide

    condition:
        any of them
}