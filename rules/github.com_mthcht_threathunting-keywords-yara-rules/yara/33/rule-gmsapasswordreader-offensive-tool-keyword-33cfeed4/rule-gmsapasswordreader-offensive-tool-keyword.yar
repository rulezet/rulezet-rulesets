rule rule_GMSAPasswordReader_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GMSAPasswordReader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GMSAPasswordReader"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GMSAPasswordReader_offensive_tool_keyword = /\/GMSAPasswordReader\./ nocase ascii wide
                        $string2_GMSAPasswordReader_offensive_tool_keyword = /\/GMSAPasswordReader\.git/ nocase ascii wide
                        $string3_GMSAPasswordReader_offensive_tool_keyword = /\\GMSAPasswordReader\./ nocase ascii wide
                        $string4_GMSAPasswordReader_offensive_tool_keyword = ">GMSAPasswordReader<" nocase ascii wide
                        $string5_GMSAPasswordReader_offensive_tool_keyword = /GMSAPasswordReader\.exe/ nocase ascii wide
                        $string6_GMSAPasswordReader_offensive_tool_keyword = /GMSAPasswordReader\.exe/ nocase ascii wide
                        $string7_GMSAPasswordReader_offensive_tool_keyword = "GMSAPasswordReader-master" nocase ascii wide
                        $string8_GMSAPasswordReader_offensive_tool_keyword = "Retrieve password for the account arobbins in the domain testlab" nocase ascii wide
                        $string9_GMSAPasswordReader_offensive_tool_keyword = "Retrieve password for the account jkohler in your current domain" nocase ascii wide
                        $string10_GMSAPasswordReader_offensive_tool_keyword = "rvazarkar/GMSAPasswordReader" nocase ascii wide

    condition:
        any of them
}