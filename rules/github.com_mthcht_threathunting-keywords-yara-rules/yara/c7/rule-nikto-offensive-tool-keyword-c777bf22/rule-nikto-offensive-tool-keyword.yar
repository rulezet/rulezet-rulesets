rule rule_nikto_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nikto' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nikto"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nikto_offensive_tool_keyword = " install nikto"
                        $string2_nikto_offensive_tool_keyword = /\snikto\.pl\s/
                        $string3_nikto_offensive_tool_keyword = /\/nikto\.git/
                        $string4_nikto_offensive_tool_keyword = /\/nikto\.pl/
                        $string5_nikto_offensive_tool_keyword = /\/nikto\.pl/
                        $string6_nikto_offensive_tool_keyword = "/sullo/nikto"
                        $string7_nikto_offensive_tool_keyword = "nikto -C all "
                        $string8_nikto_offensive_tool_keyword = "nikto/program"
                        $string9_nikto_offensive_tool_keyword = /perl\snikto\.pl\s\-h/
                        $string10_nikto_offensive_tool_keyword = /program\/replay\.pl/
                        $string11_nikto_offensive_tool_keyword = "sullo/nikto"
                        $string12_nikto_offensive_tool_keyword = "nikto -"

    condition:
        any of them
}