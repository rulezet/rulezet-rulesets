rule CACTUSTORCH
{
    meta:
        description = "Detection patterns for the tool 'CACTUSTORCH' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CACTUSTORCH"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sCACTUSTORCH\.cna/ nocase ascii wide
                        $string2 = /\/CACTUSTORCH\.git/ nocase ascii wide
                        $string3 = "1cccdb0227ae73ae4c712460d12cf2fb9316568f2f8ceae6e6e3e101a8552942" nocase ascii wide
                        $string4 = "60c72ba7ed39768fd066dda3fdc75bcb5fae6efb3a0b222a3f455526dcf08c96" nocase ascii wide
                        $string5 = /CACTUSTORCH\.hta/ nocase ascii wide
                        $string6 = /CACTUSTORCH\.js/ nocase ascii wide
                        $string7 = /CACTUSTORCH\.vba/ nocase ascii wide
                        $string8 = /CACTUSTORCH\.vbe/ nocase ascii wide
                        $string9 = /CACTUSTORCH\.vbs/ nocase ascii wide
                        $string10 = "d9ce9dfbdd4f95ad01fc05855235d6894ef878d6d02706e6c91720ee8a4fb5bf" nocase ascii wide
                        $string11 = "mdsecactivebreach/CACTUSTORCH" nocase ascii wide
                        $string12 = "TM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAACf0hwW27NyRduzckXbs3JFZvzkRdqz" nocase ascii wide

    condition:
        any of them
}