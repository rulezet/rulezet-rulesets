rule rule_saycheese_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'saycheese' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "saycheese"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_saycheese_offensive_tool_keyword = /\ssaycheese\.sh/ nocase ascii wide
                        $string2_saycheese_offensive_tool_keyword = "/ngrok http 3333 > /dev/null 2>&1"
                        $string3_saycheese_offensive_tool_keyword = /\/saycheese\.html/ nocase ascii wide
                        $string4_saycheese_offensive_tool_keyword = /\/saycheese\.sh/ nocase ascii wide
                        $string5_saycheese_offensive_tool_keyword = "d10833b7d54745c35eec76ce48c1d8a4d90a9455bcd8b81cacdc95b9304b3be3" nocase ascii wide
                        $string6_saycheese_offensive_tool_keyword = /https\:\/\/saycheese.{0,1000}\.serveo\.net/ nocase ascii wide
                        $string7_saycheese_offensive_tool_keyword = /saycheese\-master\.zip/ nocase ascii wide
                        $string8_saycheese_offensive_tool_keyword = /ssh\s\-o\sStrictHostKeyChecking\=no\s\-o\sServerAliveInterval\=60\s\-R\s.{0,1000}serveo\.net/ nocase ascii wide
                        $string9_saycheese_offensive_tool_keyword = "thelinuxchoice/saycheese"
                        $string10_saycheese_offensive_tool_keyword = /url\:\s\'forwarding_link\/post\.php\'\,/ nocase ascii wide

    condition:
        any of them
}