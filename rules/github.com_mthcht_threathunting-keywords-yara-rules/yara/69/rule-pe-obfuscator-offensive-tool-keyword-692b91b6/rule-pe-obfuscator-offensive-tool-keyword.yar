rule rule_PE_Obfuscator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PE-Obfuscator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PE-Obfuscator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PE_Obfuscator_offensive_tool_keyword = "/PE-Obfuscator" nocase ascii wide
                        $string2_PE_Obfuscator_offensive_tool_keyword = /\\out_pe\.exe/ nocase ascii wide
                        $string3_PE_Obfuscator_offensive_tool_keyword = /PE\-Obfuscator\.exe/ nocase ascii wide
                        $string4_PE_Obfuscator_offensive_tool_keyword = /PE\-Obfuscator\.git/ nocase ascii wide
                        $string5_PE_Obfuscator_offensive_tool_keyword = "PE-Obfuscator-main" nocase ascii wide
                        $string6_PE_Obfuscator_offensive_tool_keyword = /script\/xor\-bin\.py/ nocase ascii wide
                        $string7_PE_Obfuscator_offensive_tool_keyword = /xor\-bin\.py\s.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}