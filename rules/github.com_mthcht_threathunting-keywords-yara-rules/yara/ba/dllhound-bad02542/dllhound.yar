rule DLLHound
{
    meta:
        description = "Detection patterns for the tool 'DLLHound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DLLHound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sDLLHound\.ps1/ nocase ascii wide
                        $string2 = /\/DLLHound\.git/ nocase ascii wide
                        $string3 = /\/DLLHound\.ps1/ nocase ascii wide
                        $string4 = /\\DLLHound\.ps1/ nocase ascii wide
                        $string5 = /\\DLLScan_\$timestamp\.csv/ nocase ascii wide
                        $string6 = "ajm4n/DLLHound" nocase ascii wide
                        $string7 = "c9fb3bcd19b8d5dc86f3adf90f4953376910e796cddf0e2fdc1ee439be51b8de" nocase ascii wide
                        $string8 = "Start-DLLScan " nocase ascii wide
                        $string9 = "Starting DLL sideloading vulnerability scan" nocase ascii wide

    condition:
        any of them
}