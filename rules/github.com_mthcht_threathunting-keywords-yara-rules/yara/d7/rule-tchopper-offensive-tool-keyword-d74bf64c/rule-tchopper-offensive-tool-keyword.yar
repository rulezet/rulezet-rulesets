rule rule_Tchopper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Tchopper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tchopper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Tchopper_offensive_tool_keyword = /\stmp_payload\.txt/ nocase ascii wide
                        $string2_Tchopper_offensive_tool_keyword = "#1 - Smuggling binary via Service DisplayName" nocase ascii wide
                        $string3_Tchopper_offensive_tool_keyword = "#2 - Smuggling binary via WMI" nocase ascii wide
                        $string4_Tchopper_offensive_tool_keyword = /\/TChopper\.git/ nocase ascii wide
                        $string5_Tchopper_offensive_tool_keyword = /\[\+\]\stask\shas\sbeen\screated\ssuccessfully\s\s\.\.\!/ nocase ascii wide
                        $string6_Tchopper_offensive_tool_keyword = /\[\-\>\]\ssending\spayload\.\.as\schuncks/ nocase ascii wide
                        $string7_Tchopper_offensive_tool_keyword = /\\Public\\chop\.enc/ nocase ascii wide
                        $string8_Tchopper_offensive_tool_keyword = /\\TChopper\\chopper\./ nocase ascii wide
                        $string9_Tchopper_offensive_tool_keyword = /\\Tchopper\-main\.zip/ nocase ascii wide
                        $string10_Tchopper_offensive_tool_keyword = /\\tmp_payload\.txt/ nocase ascii wide
                        $string11_Tchopper_offensive_tool_keyword = "chop target username password domain filename chd wmi" nocase ascii wide
                        $string12_Tchopper_offensive_tool_keyword = /chopper\.exe\s\-m/ nocase ascii wide
                        $string13_Tchopper_offensive_tool_keyword = /chopper\.exe\s\-s/ nocase ascii wide
                        $string14_Tchopper_offensive_tool_keyword = /chopper\.exe\s\-w/ nocase ascii wide
                        $string15_Tchopper_offensive_tool_keyword = /cmd\.exe\s\/c\spowershell\s\-command\s\\"Get\-Service\s.{0,1000}chopper/ nocase ascii wide
                        $string16_Tchopper_offensive_tool_keyword = "Data Name=\"ServiceName\">chopper</Data>" nocase ascii wide
                        $string17_Tchopper_offensive_tool_keyword = "Data Name=\"ServiceName\">final_seg</Data>" nocase ascii wide
                        $string18_Tchopper_offensive_tool_keyword = "Data Name=\"ServiceName\">let me in</Data>" nocase ascii wide
                        $string19_Tchopper_offensive_tool_keyword = "lawrenceamer/Tchopper" nocase ascii wide
                        $string20_Tchopper_offensive_tool_keyword = "'svc_smuggling'" nocase ascii wide
                        $string21_Tchopper_offensive_tool_keyword = "Technique #1 - Chop Chop - Create/delete" nocase ascii wide

    condition:
        any of them
}