rule Get_NetNTLM
{
    meta:
        description = "Detection patterns for the tool 'Get-NetNTLM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Get-NetNTLM"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sGet\-NetNTLM\.ps1/ nocase ascii wide
                        $string2 = /\/Get\-NetNTLM\.git/ nocase ascii wide
                        $string3 = /\/Get\-NetNTLM\.ps1/ nocase ascii wide
                        $string4 = /\\Get\-NetNTLM\.ps1/ nocase ascii wide
                        $string5 = "cba7954a3a44198ede1f02ab8b4ce571d089b72b1dab61bd5cf004958a5e1172" nocase ascii wide
                        $string6 = "elnerd/Get-NetNTLM" nocase ascii wide
                        $string7 = "Get-NetNTLM-Hash " nocase ascii wide
                        $string8 = /NTLM\sTlRMTVNTUAACAAAABgAGADgAAAAFAomiESIzRFVmd4gAAAAAAAAAAIAAgAA\+AAAABQLODgAAAA9TAE0AQgACAAYAUwBNAEIAAQAWAFMATQBCAC0AVABPAE8ATABLAEkAVAAEABIAcwBtAGIALgBsAG8AYwBhAGwAAwAoAHMAZQByAHYAZQByADIAMAAwADMALgBzAG0AYgAuAGwAbwBjAGEAbAAFABIAcwBtAGIALgBsAG8AYwBhAGwAAAAAAA\=\=/ nocase ascii wide

    condition:
        any of them
}