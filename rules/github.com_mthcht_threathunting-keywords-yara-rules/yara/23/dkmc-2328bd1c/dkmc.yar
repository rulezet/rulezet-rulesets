rule DKMC
{
    meta:
        description = "Detection patterns for the tool 'DKMC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DKMC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DKMC\.git/ nocase ascii wide
                        $string2 = /\/dkmc\.py/ nocase ascii wide
                        $string3 = /\/sc\-loader\.exe/ nocase ascii wide
                        $string4 = /\\dkmc\.py/ nocase ascii wide
                        $string5 = /\\sc\-loader\.exe/ nocase ascii wide
                        $string6 = /DKMC\-master\.zip/ nocase ascii wide
                        $string7 = /downloadshellcodebin\.c/ nocase ascii wide
                        $string8 = /downloadshellcodebin\.exe/ nocase ascii wide
                        $string9 = /exec\-sc\-rand\.ps1/ nocase ascii wide
                        $string10 = "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIASAA0AHMASQBDAEYAVABUAEwAVgBrAEMALwB6AEUAMABPAFQAWQB" nocase ascii wide
                        $string11 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC9ZoKnCHwsOdxe" nocase ascii wide
                        $string12 = "Module to generate shellcode out of raw metasploit shellcode file" nocase ascii wide
                        $string13 = "Mr-Un1k0d3r/DKMC" nocase ascii wide
                        $string14 = /python\sdkmc\.py/ nocase ascii wide

    condition:
        any of them
}