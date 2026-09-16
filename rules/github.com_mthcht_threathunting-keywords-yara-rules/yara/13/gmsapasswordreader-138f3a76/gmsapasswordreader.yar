rule GMSAPasswordReader
{
    meta:
        description = "Detection patterns for the tool 'GMSAPasswordReader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GMSAPasswordReader"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/GMSAPasswordReader\./ nocase ascii wide
                        $string2 = /\/GMSAPasswordReader\.git/ nocase ascii wide
                        $string3 = /\\GMSAPasswordReader\./ nocase ascii wide
                        $string4 = ">GMSAPasswordReader<" nocase ascii wide
                        $string5 = /GMSAPasswordReader\.exe/ nocase ascii wide
                        $string6 = /GMSAPasswordReader\.exe/ nocase ascii wide
                        $string7 = "GMSAPasswordReader-master" nocase ascii wide
                        $string8 = "Retrieve password for the account arobbins in the domain testlab" nocase ascii wide
                        $string9 = "Retrieve password for the account jkohler in your current domain" nocase ascii wide
                        $string10 = "rvazarkar/GMSAPasswordReader" nocase ascii wide

    condition:
        any of them
}