rule rule_Moriarty_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Moriarty' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Moriarty"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Moriarty_offensive_tool_keyword = /\.exe\s\-\-list\-vulns/ nocase ascii wide
                        $string2_Moriarty_offensive_tool_keyword = /\/Moriarty\.exe/ nocase ascii wide
                        $string3_Moriarty_offensive_tool_keyword = /\/Moriarty\.git/ nocase ascii wide
                        $string4_Moriarty_offensive_tool_keyword = /\\Moriarty\.exe/ nocase ascii wide
                        $string5_Moriarty_offensive_tool_keyword = /\]\sListing\sall\svulnerabilities\sscanned\sby\sMoriarty/ nocase ascii wide
                        $string6_Moriarty_offensive_tool_keyword = "<Data Name=\"Product\">Moriarty<" nocase ascii wide
                        $string7_Moriarty_offensive_tool_keyword = "23bf773ba87ff687e14a90a2c0e552eb9b04abba32dcf81d9473f921dd44b99a" nocase ascii wide
                        $string8_Moriarty_offensive_tool_keyword = "49AD5F38-9E37-4967-9E84-FE19C7434ED7" nocase ascii wide
                        $string9_Moriarty_offensive_tool_keyword = "4c2a1547f0dab58a9db68d236d1a6aa817761b678c84b83f36d6dc31066d7cc3" nocase ascii wide
                        $string10_Moriarty_offensive_tool_keyword = "5b9dfce5f5a8bb0e00e99a77f8c7197742651de267b0e9438d54d9ba9f1137b4" nocase ascii wide
                        $string11_Moriarty_offensive_tool_keyword = "7c3c428effecb086e266482a9d18a622aa939ae380be734ab844c38aedc19a5d" nocase ascii wide
                        $string12_Moriarty_offensive_tool_keyword = "9f3c1c73211ccb972f9d7e94a2130223cab43ffc7150ff432d1dafbb4a080eaf" nocase ascii wide
                        $string13_Moriarty_offensive_tool_keyword = "b2c11ff250d4ece261e20ab73f7aeb22222698c365aa0752aa3d8a5785be8ed1" nocase ascii wide
                        $string14_Moriarty_offensive_tool_keyword = "b8531483419f4819584b69edee3089b86bab98a1c39d3058074499d76939cff5" nocase ascii wide
                        $string15_Moriarty_offensive_tool_keyword = "BC-SECURITY/Moriarty" nocase ascii wide
                        $string16_Moriarty_offensive_tool_keyword = "ea5f032c532c30628da6fc76f5a4ad6ca4057ac2322f625b12fc907beadfc545" nocase ascii wide
                        $string17_Moriarty_offensive_tool_keyword = /using\sMoriarty\.Msrc\;/ nocase ascii wide

    condition:
        any of them
}