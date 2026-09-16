rule rule_Heroinn_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Heroinn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Heroinn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Heroinn_offensive_tool_keyword = /\/Heroinn\.git/ nocase ascii wide
                        $string2_Heroinn_offensive_tool_keyword = "/Heroinn/" nocase ascii wide
                        $string3_Heroinn_offensive_tool_keyword = "/heroinn_client/"
                        $string4_Heroinn_offensive_tool_keyword = /\/shell\/shell_port\./ nocase ascii wide
                        $string5_Heroinn_offensive_tool_keyword = /\\heroinn_client\\/ nocase ascii wide
                        $string6_Heroinn_offensive_tool_keyword = "09480a5f53d380fcec0fd43f60435c4d6ad9d3decca9cfa419614353f1557a48" nocase ascii wide
                        $string7_Heroinn_offensive_tool_keyword = "0x9999997B3deF7b69c09D7a9CA65E5242fb04a764" nocase ascii wide
                        $string8_Heroinn_offensive_tool_keyword = "1HeroYcNYMhjsq8RYCx1stSaRZnQd9B9Eq" nocase ascii wide
                        $string9_Heroinn_offensive_tool_keyword = "4c0700a6f8d222d9b2023a800e0f286fc43e0354ec23ea21f9344adfd2fe12c8" nocase ascii wide
                        $string10_Heroinn_offensive_tool_keyword = "a4cc9799fdba898f24de68be43dff98a9c8a153dbf016fdd042127e4b31bbc34" nocase ascii wide
                        $string11_Heroinn_offensive_tool_keyword = "b23r0/Heroinn" nocase ascii wide
                        $string12_Heroinn_offensive_tool_keyword = "b23r0/Heroinn" nocase ascii wide
                        $string13_Heroinn_offensive_tool_keyword = "Heroinn FTP" nocase ascii wide
                        $string14_Heroinn_offensive_tool_keyword = "heroinn_client" nocase ascii wide
                        $string15_Heroinn_offensive_tool_keyword = "heroinn_core" nocase ascii wide
                        $string16_Heroinn_offensive_tool_keyword = "heroinn_ftp" nocase ascii wide
                        $string17_Heroinn_offensive_tool_keyword = "heroinn_shell" nocase ascii wide
                        $string18_Heroinn_offensive_tool_keyword = "heroinn_util" nocase ascii wide
                        $string19_Heroinn_offensive_tool_keyword = "HeroinnApp" nocase ascii wide
                        $string20_Heroinn_offensive_tool_keyword = "HeroinnProtocol" nocase ascii wide
                        $string21_Heroinn_offensive_tool_keyword = "HeroinnServerCommand" nocase ascii wide
                        $string22_Heroinn_offensive_tool_keyword = "th3rd/heroinn" nocase ascii wide

    condition:
        any of them
}