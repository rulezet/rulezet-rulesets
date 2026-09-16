rule rule_Get_NetNTLM_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Get-NetNTLM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Get-NetNTLM"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Get_NetNTLM_offensive_tool_keyword = /\sGet\-NetNTLM\.ps1/ nocase ascii wide
                        $string2_Get_NetNTLM_offensive_tool_keyword = /\/Get\-NetNTLM\.git/ nocase ascii wide
                        $string3_Get_NetNTLM_offensive_tool_keyword = /\/Get\-NetNTLM\.ps1/ nocase ascii wide
                        $string4_Get_NetNTLM_offensive_tool_keyword = /\\Get\-NetNTLM\.ps1/ nocase ascii wide
                        $string5_Get_NetNTLM_offensive_tool_keyword = "cba7954a3a44198ede1f02ab8b4ce571d089b72b1dab61bd5cf004958a5e1172" nocase ascii wide
                        $string6_Get_NetNTLM_offensive_tool_keyword = "elnerd/Get-NetNTLM" nocase ascii wide
                        $string7_Get_NetNTLM_offensive_tool_keyword = "Get-NetNTLM-Hash " nocase ascii wide
                        $string8_Get_NetNTLM_offensive_tool_keyword = /NTLM\sTlRMTVNTUAACAAAABgAGADgAAAAFAomiESIzRFVmd4gAAAAAAAAAAIAAgAA\+AAAABQLODgAAAA9TAE0AQgACAAYAUwBNAEIAAQAWAFMATQBCAC0AVABPAE8ATABLAEkAVAAEABIAcwBtAGIALgBsAG8AYwBhAGwAAwAoAHMAZQByAHYAZQByADIAMAAwADMALgBzAG0AYgAuAGwAbwBjAGEAbAAFABIAcwBtAGIALgBsAG8AYwBhAGwAAAAAAA\=\=/ nocase ascii wide

    condition:
        any of them
}