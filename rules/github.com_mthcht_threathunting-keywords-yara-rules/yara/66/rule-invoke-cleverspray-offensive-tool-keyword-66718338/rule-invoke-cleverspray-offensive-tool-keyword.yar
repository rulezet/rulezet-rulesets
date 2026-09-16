rule rule_Invoke_CleverSpray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-CleverSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-CleverSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_CleverSpray_offensive_tool_keyword = /\$AllCurrentPwdDiscovered/ nocase ascii wide
                        $string2_Invoke_CleverSpray_offensive_tool_keyword = /\$TotalNbCurrentPwdDiscovered/ nocase ascii wide
                        $string3_Invoke_CleverSpray_offensive_tool_keyword = /\/Invoke\-CleverSpray\.git/ nocase ascii wide
                        $string4_Invoke_CleverSpray_offensive_tool_keyword = /\[\!\]\sPassword\sspraying\swill\sbe\sconducted/ nocase ascii wide
                        $string5_Invoke_CleverSpray_offensive_tool_keyword = /\[\!\]\sThe\spassword\s.{0,1000}\swill\sbe\ssprayed\son\stargeted\suser\saccounts\shaving/ nocase ascii wide
                        $string6_Invoke_CleverSpray_offensive_tool_keyword = "fdb1df0047a31328f0796bd07caf642efc35651ad78389025eb5afa2748bcd04" nocase ascii wide
                        $string7_Invoke_CleverSpray_offensive_tool_keyword = "Invoke-CleverSpray" nocase ascii wide
                        $string8_Invoke_CleverSpray_offensive_tool_keyword = /Invoke\-CleverSpray\.ps1/ nocase ascii wide
                        $string9_Invoke_CleverSpray_offensive_tool_keyword = "Please use the -Password option to specify a unique password to spray" nocase ascii wide
                        $string10_Invoke_CleverSpray_offensive_tool_keyword = "Please use the -User option to specify a unique username to spray" nocase ascii wide
                        $string11_Invoke_CleverSpray_offensive_tool_keyword = "wavestone-cdt/Invoke-CleverSpray" nocase ascii wide

    condition:
        any of them
}