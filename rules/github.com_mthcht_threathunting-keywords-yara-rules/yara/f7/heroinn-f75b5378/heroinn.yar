rule Heroinn
{
    meta:
        description = "Detection patterns for the tool 'Heroinn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Heroinn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Heroinn\.git/ nocase ascii wide
                        $string2 = "/Heroinn/" nocase ascii wide
                        $string3 = "/heroinn_client/"
                        $string4 = /\/shell\/shell_port\./ nocase ascii wide
                        $string5 = /\\heroinn_client\\/ nocase ascii wide
                        $string6 = "09480a5f53d380fcec0fd43f60435c4d6ad9d3decca9cfa419614353f1557a48" nocase ascii wide
                        $string7 = "0x9999997B3deF7b69c09D7a9CA65E5242fb04a764" nocase ascii wide
                        $string8 = "1HeroYcNYMhjsq8RYCx1stSaRZnQd9B9Eq" nocase ascii wide
                        $string9 = "4c0700a6f8d222d9b2023a800e0f286fc43e0354ec23ea21f9344adfd2fe12c8" nocase ascii wide
                        $string10 = "a4cc9799fdba898f24de68be43dff98a9c8a153dbf016fdd042127e4b31bbc34" nocase ascii wide
                        $string11 = "b23r0/Heroinn" nocase ascii wide
                        $string12 = "b23r0/Heroinn" nocase ascii wide
                        $string13 = "Heroinn FTP" nocase ascii wide
                        $string14 = "heroinn_client" nocase ascii wide
                        $string15 = "heroinn_core" nocase ascii wide
                        $string16 = "heroinn_ftp" nocase ascii wide
                        $string17 = "heroinn_shell" nocase ascii wide
                        $string18 = "heroinn_util" nocase ascii wide
                        $string19 = "HeroinnApp" nocase ascii wide
                        $string20 = "HeroinnProtocol" nocase ascii wide
                        $string21 = "HeroinnServerCommand" nocase ascii wide
                        $string22 = "th3rd/heroinn" nocase ascii wide

    condition:
        any of them
}