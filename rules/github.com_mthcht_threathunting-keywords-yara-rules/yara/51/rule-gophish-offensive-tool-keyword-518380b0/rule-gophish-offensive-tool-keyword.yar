rule rule_gophish_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gophish' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gophish"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gophish_offensive_tool_keyword = " evilginx" nocase ascii wide
                        $string2_gophish_offensive_tool_keyword = "/evilginx" nocase ascii wide
                        $string3_gophish_offensive_tool_keyword = /\/gophish\.db/ nocase ascii wide
                        $string4_gophish_offensive_tool_keyword = "/gophish/" nocase ascii wide
                        $string5_gophish_offensive_tool_keyword = "c121f7d62fa5ecd27c3aaae5737a3de8f2e4def0c182058b6dd824aa92351e9c" nocase ascii wide
                        $string6_gophish_offensive_tool_keyword = /evilfeed\.go/ nocase ascii wide
                        $string7_gophish_offensive_tool_keyword = "evilginx-linux"
                        $string8_gophish_offensive_tool_keyword = "evilgophish" nocase ascii wide
                        $string9_gophish_offensive_tool_keyword = /gophish.{0,1000}phish\.go/ nocase ascii wide
                        $string10_gophish_offensive_tool_keyword = /gophish\.go/ nocase ascii wide
                        $string11_gophish_offensive_tool_keyword = "gophish/gophish" nocase ascii wide
                        $string12_gophish_offensive_tool_keyword = "localhost:1337" nocase ascii wide
                        $string13_gophish_offensive_tool_keyword = "lures create " nocase ascii wide
                        $string14_gophish_offensive_tool_keyword = /phish_test\.go/ nocase ascii wide
                        $string15_gophish_offensive_tool_keyword = "phishlets " nocase ascii wide
                        $string16_gophish_offensive_tool_keyword = "sneaky_gophish" nocase ascii wide
                        $string17_gophish_offensive_tool_keyword = "X-Gophish-Contact" nocase ascii wide

    condition:
        any of them
}