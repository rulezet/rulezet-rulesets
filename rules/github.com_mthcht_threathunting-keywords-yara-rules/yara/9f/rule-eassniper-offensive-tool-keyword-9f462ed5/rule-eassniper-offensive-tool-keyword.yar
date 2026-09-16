rule rule_EASSniper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EASSniper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EASSniper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EASSniper_offensive_tool_keyword = /\sEASSniper\.ps1/ nocase ascii wide
                        $string2_EASSniper_offensive_tool_keyword = /\seas\-valid\-users\.txt/ nocase ascii wide
                        $string3_EASSniper_offensive_tool_keyword = /\sowa\-sprayed\-creds\.txt/ nocase ascii wide
                        $string4_EASSniper_offensive_tool_keyword = /\/EASSniper\.git/ nocase ascii wide
                        $string5_EASSniper_offensive_tool_keyword = /\/EASSniper\.ps1/ nocase ascii wide
                        $string6_EASSniper_offensive_tool_keyword = /\/eas\-valid\-users\.txt/
                        $string7_EASSniper_offensive_tool_keyword = /\/owa\-sprayed\-creds\.txt/
                        $string8_EASSniper_offensive_tool_keyword = /\\EASSniper\.ps1/ nocase ascii wide
                        $string9_EASSniper_offensive_tool_keyword = /\\eas\-valid\-users\.txt/ nocase ascii wide
                        $string10_EASSniper_offensive_tool_keyword = /\\owa\-sprayed\-creds\.txt/ nocase ascii wide
                        $string11_EASSniper_offensive_tool_keyword = /\]\sNow\sspraying\sEAS\sportal\sat\shttps\:\/\/.{0,1000}\/Microsoft\-Server\-ActiveSync/ nocase ascii wide
                        $string12_EASSniper_offensive_tool_keyword = "002fa7c3b308536f94ff10852afcfbb0285608d259a43277e69751ab7db48e04" nocase ascii wide
                        $string13_EASSniper_offensive_tool_keyword = "fugawi/EASSniper" nocase ascii wide
                        $string14_EASSniper_offensive_tool_keyword = "Invoke-PasswordSprayEAS" nocase ascii wide
                        $string15_EASSniper_offensive_tool_keyword = "Invoke-UsernameHarvestEAS" nocase ascii wide
                        $string16_EASSniper_offensive_tool_keyword = "Password Spraying EAS at https://" nocase ascii wide

    condition:
        any of them
}