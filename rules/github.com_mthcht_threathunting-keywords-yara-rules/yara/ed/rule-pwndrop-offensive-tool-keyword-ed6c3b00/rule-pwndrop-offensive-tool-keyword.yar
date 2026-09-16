rule rule_pwndrop_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pwndrop' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pwndrop"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pwndrop_offensive_tool_keyword = /\.\/pwndrop\s/
                        $string2_pwndrop_offensive_tool_keyword = /\/pwndrop\.git/ nocase ascii wide
                        $string3_pwndrop_offensive_tool_keyword = /\/pwndrop\.ini/
                        $string4_pwndrop_offensive_tool_keyword = "/usr/local/pwndrop/"
                        $string5_pwndrop_offensive_tool_keyword = "kgretzky/pwndrop" nocase ascii wide
                        $string6_pwndrop_offensive_tool_keyword = "pwndrop install" nocase ascii wide
                        $string7_pwndrop_offensive_tool_keyword = "pwndrop start" nocase ascii wide
                        $string8_pwndrop_offensive_tool_keyword = "pwndrop status" nocase ascii wide
                        $string9_pwndrop_offensive_tool_keyword = "pwndrop stop" nocase ascii wide
                        $string10_pwndrop_offensive_tool_keyword = "pwndrop-linux-amd64"
                        $string11_pwndrop_offensive_tool_keyword = "pwndrop-master" nocase ascii wide

    condition:
        any of them
}