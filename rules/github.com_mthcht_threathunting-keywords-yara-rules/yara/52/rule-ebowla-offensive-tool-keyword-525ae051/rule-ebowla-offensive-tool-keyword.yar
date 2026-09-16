rule rule_Ebowla_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Ebowla' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ebowla"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Ebowla_offensive_tool_keyword = /\sebowla\.py/ nocase ascii wide
                        $string2_Ebowla_offensive_tool_keyword = /\/Ebowla\.git/ nocase ascii wide
                        $string3_Ebowla_offensive_tool_keyword = /\/ebowla\.py/ nocase ascii wide
                        $string4_Ebowla_offensive_tool_keyword = /\\ebowla\.py/ nocase ascii wide
                        $string5_Ebowla_offensive_tool_keyword = /DllLoaderLoader\.exe/ nocase ascii wide
                        $string6_Ebowla_offensive_tool_keyword = /Ebowla\-master\.zip/ nocase ascii wide
                        $string7_Ebowla_offensive_tool_keyword = /exe_dll_shellcode\sgenetic\.config/ nocase ascii wide
                        $string8_Ebowla_offensive_tool_keyword = "Genetic-Malware/Ebowla" nocase ascii wide

    condition:
        any of them
}