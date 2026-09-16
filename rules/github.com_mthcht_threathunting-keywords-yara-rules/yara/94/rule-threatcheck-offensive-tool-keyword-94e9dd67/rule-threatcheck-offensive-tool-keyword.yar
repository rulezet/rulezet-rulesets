rule rule_ThreatCheck_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ThreatCheck' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThreatCheck"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ThreatCheck_offensive_tool_keyword = /\s\-f\s.{0,1000}\.bin\s\-e\sAMSI/ nocase ascii wide
                        $string2_ThreatCheck_offensive_tool_keyword = /\s\-f\s.{0,1000}\.bin\s\-e\sDefender/ nocase ascii wide
                        $string3_ThreatCheck_offensive_tool_keyword = /\s\-Scan\s\-ScanType\s3\s\-File\s.{0,1000}\s\-DisableRemediation\s\-Trace\s\-Level\s0x10/ nocase ascii wide
                        $string4_ThreatCheck_offensive_tool_keyword = /\/ThreatCheck\.git/ nocase ascii wide
                        $string5_ThreatCheck_offensive_tool_keyword = /\\Blackout\.sys/ nocase ascii wide
                        $string6_ThreatCheck_offensive_tool_keyword = /\\NimBlackout/ nocase ascii wide
                        $string7_ThreatCheck_offensive_tool_keyword = "3EC9B9A8-0AFE-44A7-8B95-7F60E750F042" nocase ascii wide
                        $string8_ThreatCheck_offensive_tool_keyword = "76f677acfe19ca1e1e39c391e4923dc38e1e3f752097c5808c171c1d5228194e" nocase ascii wide
                        $string9_ThreatCheck_offensive_tool_keyword = /C\:\\Temp\\file\.exe/ nocase ascii wide
                        $string10_ThreatCheck_offensive_tool_keyword = /NimBlackout.{0,1000}\.exe/ nocase ascii wide
                        $string11_ThreatCheck_offensive_tool_keyword = /NimBlackout\./ nocase ascii wide
                        $string12_ThreatCheck_offensive_tool_keyword = "NimBlackout-main" nocase ascii wide
                        $string13_ThreatCheck_offensive_tool_keyword = "rasta-mouse/ThreatCheck" nocase ascii wide
                        $string14_ThreatCheck_offensive_tool_keyword = /ThreatCheck\.csproj/ nocase ascii wide
                        $string15_ThreatCheck_offensive_tool_keyword = /ThreatCheck\.csproj/ nocase ascii wide
                        $string16_ThreatCheck_offensive_tool_keyword = /ThreatCheck\.exe/ nocase ascii wide
                        $string17_ThreatCheck_offensive_tool_keyword = "ThreatCheck-master" nocase ascii wide

    condition:
        any of them
}