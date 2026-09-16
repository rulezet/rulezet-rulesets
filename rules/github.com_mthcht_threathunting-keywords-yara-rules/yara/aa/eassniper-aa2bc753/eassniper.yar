rule EASSniper
{
    meta:
        description = "Detection patterns for the tool 'EASSniper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EASSniper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sEASSniper\.ps1/ nocase ascii wide
                        $string2 = /\seas\-valid\-users\.txt/ nocase ascii wide
                        $string3 = /\sowa\-sprayed\-creds\.txt/ nocase ascii wide
                        $string4 = /\/EASSniper\.git/ nocase ascii wide
                        $string5 = /\/EASSniper\.ps1/ nocase ascii wide
                        $string6 = /\/eas\-valid\-users\.txt/
                        $string7 = /\/owa\-sprayed\-creds\.txt/
                        $string8 = /\\EASSniper\.ps1/ nocase ascii wide
                        $string9 = /\\eas\-valid\-users\.txt/ nocase ascii wide
                        $string10 = /\\owa\-sprayed\-creds\.txt/ nocase ascii wide
                        $string11 = /\]\sNow\sspraying\sEAS\sportal\sat\shttps\:\/\/.{0,1000}\/Microsoft\-Server\-ActiveSync/ nocase ascii wide
                        $string12 = "002fa7c3b308536f94ff10852afcfbb0285608d259a43277e69751ab7db48e04" nocase ascii wide
                        $string13 = "fugawi/EASSniper" nocase ascii wide
                        $string14 = "Invoke-PasswordSprayEAS" nocase ascii wide
                        $string15 = "Invoke-UsernameHarvestEAS" nocase ascii wide
                        $string16 = "Password Spraying EAS at https://" nocase ascii wide

    condition:
        any of them
}