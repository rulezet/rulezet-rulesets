rule rule_CACTUSTORCH_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CACTUSTORCH' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CACTUSTORCH"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CACTUSTORCH_offensive_tool_keyword = /\sCACTUSTORCH\.cna/ nocase ascii wide
                        $string2_CACTUSTORCH_offensive_tool_keyword = /\/CACTUSTORCH\.git/ nocase ascii wide
                        $string3_CACTUSTORCH_offensive_tool_keyword = "1cccdb0227ae73ae4c712460d12cf2fb9316568f2f8ceae6e6e3e101a8552942" nocase ascii wide
                        $string4_CACTUSTORCH_offensive_tool_keyword = "60c72ba7ed39768fd066dda3fdc75bcb5fae6efb3a0b222a3f455526dcf08c96" nocase ascii wide
                        $string5_CACTUSTORCH_offensive_tool_keyword = /CACTUSTORCH\.hta/ nocase ascii wide
                        $string6_CACTUSTORCH_offensive_tool_keyword = /CACTUSTORCH\.js/ nocase ascii wide
                        $string7_CACTUSTORCH_offensive_tool_keyword = /CACTUSTORCH\.vba/ nocase ascii wide
                        $string8_CACTUSTORCH_offensive_tool_keyword = /CACTUSTORCH\.vbe/ nocase ascii wide
                        $string9_CACTUSTORCH_offensive_tool_keyword = /CACTUSTORCH\.vbs/ nocase ascii wide
                        $string10_CACTUSTORCH_offensive_tool_keyword = "d9ce9dfbdd4f95ad01fc05855235d6894ef878d6d02706e6c91720ee8a4fb5bf" nocase ascii wide
                        $string11_CACTUSTORCH_offensive_tool_keyword = "mdsecactivebreach/CACTUSTORCH" nocase ascii wide
                        $string12_CACTUSTORCH_offensive_tool_keyword = "TM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAACf0hwW27NyRduzckXbs3JFZvzkRdqz" nocase ascii wide

    condition:
        any of them
}