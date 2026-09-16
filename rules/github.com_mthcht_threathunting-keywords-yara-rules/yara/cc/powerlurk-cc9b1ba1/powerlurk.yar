rule Powerlurk
{
    meta:
        description = "Detection patterns for the tool 'Powerlurk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Powerlurk"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sAdd\-KeeThiefLurker\.ps1/ nocase ascii wide
                        $string2 = " -EventName KeeThief -WMI" nocase ascii wide
                        $string3 = " -EventName WmiBackdoor -PermanentCommand " nocase ascii wide
                        $string4 = /\sPowerLurk\.ps1/ nocase ascii wide
                        $string5 = /\/Add\-KeeThiefLurker\.ps1/ nocase ascii wide
                        $string6 = /\/PowerLurk\.git/ nocase ascii wide
                        $string7 = /\/PowerLurk\.ps1/ nocase ascii wide
                        $string8 = /\\Add\-KeeThiefLurker\.ps1/ nocase ascii wide
                        $string9 = /\\PowerLurk\.ps1/ nocase ascii wide
                        $string10 = /\\PowerLurk\-main/ nocase ascii wide
                        $string11 = "238111f4c27f2bad38c5b5eac85aacf4305baaa7c854911e3cbffe7a58cc9964" nocase ascii wide
                        $string12 = "7b0HYBxJliUmL23Ke39K9UrX4HShCIBgEyTYkEAQ7MGIzeaS7B1pRyMpqyqBymVWZV1mFkDM7Z28995777333nvvvfe6O51OJ" nocase ascii wide
                        $string13 = "81c3f4341d0cecc16beaae19c88e54dda2730a4eaf06cc0fea0119822d7482c3" nocase ascii wide
                        $string14 = "Add-KeeThiefLurker " nocase ascii wide
                        $string15 = "Find-KeePassconfig " nocase ascii wide
                        $string16 = "function Find-KeePassconfig" nocase ascii wide
                        $string17 = "function Local:Get-KeePassINIFields" nocase ascii wide
                        $string18 = "Get-KeePassDatabaseKey " nocase ascii wide
                        $string19 = "Register-MaliciousWmiEvent" nocase ascii wide
                        $string20 = /Registry\sKeeTheifLurker\s.{0,1000}\sCreated/ nocase ascii wide
                        $string21 = "Remove-KeeThiefLurker " nocase ascii wide
                        $string22 = "Remove-TemplateLurker -EventName " nocase ascii wide
                        $string23 = "Sw4mpf0x/PowerLurk" nocase ascii wide
                        $string24 = "WMI KeeTheifLurker " nocase ascii wide
                        $string25 = /WMI\sKeeTheifLurker\s.{0,1000}\sCreated/ nocase ascii wide

    condition:
        any of them
}