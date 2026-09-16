rule ThreatCheck
{
    meta:
        description = "Detection patterns for the tool 'ThreatCheck' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThreatCheck"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-f\s.{0,1000}\.bin\s\-e\sAMSI/ nocase ascii wide
                        $string2 = /\s\-f\s.{0,1000}\.bin\s\-e\sDefender/ nocase ascii wide
                        $string3 = /\s\-Scan\s\-ScanType\s3\s\-File\s.{0,1000}\s\-DisableRemediation\s\-Trace\s\-Level\s0x10/ nocase ascii wide
                        $string4 = /\/ThreatCheck\.git/ nocase ascii wide
                        $string5 = /\\Blackout\.sys/ nocase ascii wide
                        $string6 = /\\NimBlackout/ nocase ascii wide
                        $string7 = "3EC9B9A8-0AFE-44A7-8B95-7F60E750F042" nocase ascii wide
                        $string8 = "76f677acfe19ca1e1e39c391e4923dc38e1e3f752097c5808c171c1d5228194e" nocase ascii wide
                        $string9 = /C\:\\Temp\\file\.exe/ nocase ascii wide
                        $string10 = /NimBlackout.{0,1000}\.exe/ nocase ascii wide
                        $string11 = /NimBlackout\./ nocase ascii wide
                        $string12 = "NimBlackout-main" nocase ascii wide
                        $string13 = "rasta-mouse/ThreatCheck" nocase ascii wide
                        $string14 = /ThreatCheck\.csproj/ nocase ascii wide
                        $string15 = /ThreatCheck\.csproj/ nocase ascii wide
                        $string16 = /ThreatCheck\.exe/ nocase ascii wide
                        $string17 = "ThreatCheck-master" nocase ascii wide

    condition:
        any of them
}