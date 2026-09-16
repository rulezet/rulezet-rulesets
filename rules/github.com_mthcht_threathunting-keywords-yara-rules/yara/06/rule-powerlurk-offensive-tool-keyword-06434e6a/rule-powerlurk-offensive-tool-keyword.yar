rule rule_Powerlurk_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Powerlurk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Powerlurk"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Powerlurk_offensive_tool_keyword = /\sAdd\-KeeThiefLurker\.ps1/ nocase ascii wide
                        $string2_Powerlurk_offensive_tool_keyword = " -EventName KeeThief -WMI" nocase ascii wide
                        $string3_Powerlurk_offensive_tool_keyword = " -EventName WmiBackdoor -PermanentCommand " nocase ascii wide
                        $string4_Powerlurk_offensive_tool_keyword = /\sPowerLurk\.ps1/ nocase ascii wide
                        $string5_Powerlurk_offensive_tool_keyword = /\/Add\-KeeThiefLurker\.ps1/ nocase ascii wide
                        $string6_Powerlurk_offensive_tool_keyword = /\/PowerLurk\.git/ nocase ascii wide
                        $string7_Powerlurk_offensive_tool_keyword = /\/PowerLurk\.ps1/ nocase ascii wide
                        $string8_Powerlurk_offensive_tool_keyword = /\\Add\-KeeThiefLurker\.ps1/ nocase ascii wide
                        $string9_Powerlurk_offensive_tool_keyword = /\\PowerLurk\.ps1/ nocase ascii wide
                        $string10_Powerlurk_offensive_tool_keyword = /\\PowerLurk\-main/ nocase ascii wide
                        $string11_Powerlurk_offensive_tool_keyword = "238111f4c27f2bad38c5b5eac85aacf4305baaa7c854911e3cbffe7a58cc9964" nocase ascii wide
                        $string12_Powerlurk_offensive_tool_keyword = "7b0HYBxJliUmL23Ke39K9UrX4HShCIBgEyTYkEAQ7MGIzeaS7B1pRyMpqyqBymVWZV1mFkDM7Z28995777333nvvvfe6O51OJ" nocase ascii wide
                        $string13_Powerlurk_offensive_tool_keyword = "81c3f4341d0cecc16beaae19c88e54dda2730a4eaf06cc0fea0119822d7482c3" nocase ascii wide
                        $string14_Powerlurk_offensive_tool_keyword = "Add-KeeThiefLurker " nocase ascii wide
                        $string15_Powerlurk_offensive_tool_keyword = "Find-KeePassconfig " nocase ascii wide
                        $string16_Powerlurk_offensive_tool_keyword = "function Find-KeePassconfig" nocase ascii wide
                        $string17_Powerlurk_offensive_tool_keyword = "function Local:Get-KeePassINIFields" nocase ascii wide
                        $string18_Powerlurk_offensive_tool_keyword = "Get-KeePassDatabaseKey " nocase ascii wide
                        $string19_Powerlurk_offensive_tool_keyword = "Register-MaliciousWmiEvent" nocase ascii wide
                        $string20_Powerlurk_offensive_tool_keyword = /Registry\sKeeTheifLurker\s.{0,1000}\sCreated/ nocase ascii wide
                        $string21_Powerlurk_offensive_tool_keyword = "Remove-KeeThiefLurker " nocase ascii wide
                        $string22_Powerlurk_offensive_tool_keyword = "Remove-TemplateLurker -EventName " nocase ascii wide
                        $string23_Powerlurk_offensive_tool_keyword = "Sw4mpf0x/PowerLurk" nocase ascii wide
                        $string24_Powerlurk_offensive_tool_keyword = "WMI KeeTheifLurker " nocase ascii wide
                        $string25_Powerlurk_offensive_tool_keyword = /WMI\sKeeTheifLurker\s.{0,1000}\sCreated/ nocase ascii wide

    condition:
        any of them
}