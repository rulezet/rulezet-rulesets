rule rule_PowerBruteLogon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowerBruteLogon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerBruteLogon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PowerBruteLogon_offensive_tool_keyword = "/PowerBruteLogon" nocase ascii wide
                        $string2_PowerBruteLogon_offensive_tool_keyword = /\\PowerBruteLogon/ nocase ascii wide
                        $string3_PowerBruteLogon_offensive_tool_keyword = "3d686ba6d6985ff3febf3cd3d45cb5eb18eff45bfec74142865ded01f9c00503" nocase ascii wide
                        $string4_PowerBruteLogon_offensive_tool_keyword = "4b23fd7b0179a37fe15bf38ea9ccb0202202d36dcaa882c58a66c1979d37e92c" nocase ascii wide
                        $string5_PowerBruteLogon_offensive_tool_keyword = "5f8fdd73abce168e8b44db54ad203a66d4983d1fd2563bb5922c0aaef9abc4ea" nocase ascii wide
                        $string6_PowerBruteLogon_offensive_tool_keyword = "75682eac28a36100019a0606879be2a615e6c221b212833b2eb9ab83f6360cd6" nocase ascii wide
                        $string7_PowerBruteLogon_offensive_tool_keyword = "Invoke-BruteAvailableLogons" nocase ascii wide
                        $string8_PowerBruteLogon_offensive_tool_keyword = "Invoke-BruteLogonAccount" nocase ascii wide
                        $string9_PowerBruteLogon_offensive_tool_keyword = "Invoke-BruteLogonList" nocase ascii wide
                        $string10_PowerBruteLogon_offensive_tool_keyword = /PowerBruteLogon\./ nocase ascii wide
                        $string11_PowerBruteLogon_offensive_tool_keyword = /PowerBruteLogon\.zip/ nocase ascii wide

    condition:
        any of them
}