rule Tchopper
{
    meta:
        description = "Detection patterns for the tool 'Tchopper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tchopper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\stmp_payload\.txt/ nocase ascii wide
                        $string2 = "#1 - Smuggling binary via Service DisplayName" nocase ascii wide
                        $string3 = "#2 - Smuggling binary via WMI" nocase ascii wide
                        $string4 = /\/TChopper\.git/ nocase ascii wide
                        $string5 = /\[\+\]\stask\shas\sbeen\screated\ssuccessfully\s\s\.\.\!/ nocase ascii wide
                        $string6 = /\[\-\>\]\ssending\spayload\.\.as\schuncks/ nocase ascii wide
                        $string7 = /\\Public\\chop\.enc/ nocase ascii wide
                        $string8 = /\\TChopper\\chopper\./ nocase ascii wide
                        $string9 = /\\Tchopper\-main\.zip/ nocase ascii wide
                        $string10 = /\\tmp_payload\.txt/ nocase ascii wide
                        $string11 = "chop target username password domain filename chd wmi" nocase ascii wide
                        $string12 = /chopper\.exe\s\-m/ nocase ascii wide
                        $string13 = /chopper\.exe\s\-s/ nocase ascii wide
                        $string14 = /chopper\.exe\s\-w/ nocase ascii wide
                        $string15 = /cmd\.exe\s\/c\spowershell\s\-command\s\\"Get\-Service\s.{0,1000}chopper/ nocase ascii wide
                        $string16 = "Data Name=\"ServiceName\">chopper</Data>" nocase ascii wide
                        $string17 = "Data Name=\"ServiceName\">final_seg</Data>" nocase ascii wide
                        $string18 = "Data Name=\"ServiceName\">let me in</Data>" nocase ascii wide
                        $string19 = "lawrenceamer/Tchopper" nocase ascii wide
                        $string20 = "'svc_smuggling'" nocase ascii wide
                        $string21 = "Technique #1 - Chop Chop - Create/delete" nocase ascii wide

    condition:
        any of them
}