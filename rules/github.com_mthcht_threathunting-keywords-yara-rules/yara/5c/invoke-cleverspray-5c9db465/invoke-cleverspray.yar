rule Invoke_CleverSpray
{
    meta:
        description = "Detection patterns for the tool 'Invoke-CleverSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-CleverSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\$AllCurrentPwdDiscovered/ nocase ascii wide
                        $string2 = /\$TotalNbCurrentPwdDiscovered/ nocase ascii wide
                        $string3 = /\/Invoke\-CleverSpray\.git/ nocase ascii wide
                        $string4 = /\[\!\]\sPassword\sspraying\swill\sbe\sconducted/ nocase ascii wide
                        $string5 = /\[\!\]\sThe\spassword\s.{0,1000}\swill\sbe\ssprayed\son\stargeted\suser\saccounts\shaving/ nocase ascii wide
                        $string6 = "fdb1df0047a31328f0796bd07caf642efc35651ad78389025eb5afa2748bcd04" nocase ascii wide
                        $string7 = "Invoke-CleverSpray" nocase ascii wide
                        $string8 = /Invoke\-CleverSpray\.ps1/ nocase ascii wide
                        $string9 = "Please use the -Password option to specify a unique password to spray" nocase ascii wide
                        $string10 = "Please use the -User option to specify a unique username to spray" nocase ascii wide
                        $string11 = "wavestone-cdt/Invoke-CleverSpray" nocase ascii wide

    condition:
        any of them
}