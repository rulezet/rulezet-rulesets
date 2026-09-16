rule rule_DLLHound_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DLLHound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DLLHound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DLLHound_offensive_tool_keyword = /\sDLLHound\.ps1/ nocase ascii wide
                        $string2_DLLHound_offensive_tool_keyword = /\/DLLHound\.git/ nocase ascii wide
                        $string3_DLLHound_offensive_tool_keyword = /\/DLLHound\.ps1/ nocase ascii wide
                        $string4_DLLHound_offensive_tool_keyword = /\\DLLHound\.ps1/ nocase ascii wide
                        $string5_DLLHound_offensive_tool_keyword = /\\DLLScan_\$timestamp\.csv/ nocase ascii wide
                        $string6_DLLHound_offensive_tool_keyword = "ajm4n/DLLHound" nocase ascii wide
                        $string7_DLLHound_offensive_tool_keyword = "c9fb3bcd19b8d5dc86f3adf90f4953376910e796cddf0e2fdc1ee439be51b8de" nocase ascii wide
                        $string8_DLLHound_offensive_tool_keyword = "Start-DLLScan " nocase ascii wide
                        $string9_DLLHound_offensive_tool_keyword = "Starting DLL sideloading vulnerability scan" nocase ascii wide

    condition:
        any of them
}