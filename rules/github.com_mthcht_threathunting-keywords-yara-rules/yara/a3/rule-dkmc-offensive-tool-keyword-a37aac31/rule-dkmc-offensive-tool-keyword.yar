rule rule_DKMC_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DKMC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DKMC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DKMC_offensive_tool_keyword = /\/DKMC\.git/ nocase ascii wide
                        $string2_DKMC_offensive_tool_keyword = /\/dkmc\.py/ nocase ascii wide
                        $string3_DKMC_offensive_tool_keyword = /\/sc\-loader\.exe/ nocase ascii wide
                        $string4_DKMC_offensive_tool_keyword = /\\dkmc\.py/ nocase ascii wide
                        $string5_DKMC_offensive_tool_keyword = /\\sc\-loader\.exe/ nocase ascii wide
                        $string6_DKMC_offensive_tool_keyword = /DKMC\-master\.zip/ nocase ascii wide
                        $string7_DKMC_offensive_tool_keyword = /downloadshellcodebin\.c/ nocase ascii wide
                        $string8_DKMC_offensive_tool_keyword = /downloadshellcodebin\.exe/ nocase ascii wide
                        $string9_DKMC_offensive_tool_keyword = /exec\-sc\-rand\.ps1/ nocase ascii wide
                        $string10_DKMC_offensive_tool_keyword = "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIASAA0AHMASQBDAEYAVABUAEwAVgBrAEMALwB6AEUAMABPAFQAWQB" nocase ascii wide
                        $string11_DKMC_offensive_tool_keyword = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC9ZoKnCHwsOdxe" nocase ascii wide
                        $string12_DKMC_offensive_tool_keyword = "Module to generate shellcode out of raw metasploit shellcode file" nocase ascii wide
                        $string13_DKMC_offensive_tool_keyword = "Mr-Un1k0d3r/DKMC" nocase ascii wide
                        $string14_DKMC_offensive_tool_keyword = /python\sdkmc\.py/ nocase ascii wide

    condition:
        any of them
}