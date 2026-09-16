rule PE_Obfuscator
{
    meta:
        description = "Detection patterns for the tool 'PE-Obfuscator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PE-Obfuscator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/PE-Obfuscator" nocase ascii wide
                        $string2 = /\\out_pe\.exe/ nocase ascii wide
                        $string3 = /PE\-Obfuscator\.exe/ nocase ascii wide
                        $string4 = /PE\-Obfuscator\.git/ nocase ascii wide
                        $string5 = "PE-Obfuscator-main" nocase ascii wide
                        $string6 = /script\/xor\-bin\.py/ nocase ascii wide
                        $string7 = /xor\-bin\.py\s.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}