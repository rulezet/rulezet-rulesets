rule rule_HadesLdr_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HadesLdr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HadesLdr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HadesLdr_offensive_tool_keyword = /\s\-h\s.{0,1000}\-p\s.{0,1000}\s\-c\scypher\.bin\s\-k\skey\.bin/ nocase ascii wide
                        $string2_HadesLdr_offensive_tool_keyword = /\/HadesLdr\.git/ nocase ascii wide
                        $string3_HadesLdr_offensive_tool_keyword = /\/scripts\/xor\.py/ nocase ascii wide
                        $string4_HadesLdr_offensive_tool_keyword = "CognisysGroup/HadesLdr" nocase ascii wide
                        $string5_HadesLdr_offensive_tool_keyword = "HadesLdr-main" nocase ascii wide
                        $string6_HadesLdr_offensive_tool_keyword = /IDSyscall\.exe/ nocase ascii wide
                        $string7_HadesLdr_offensive_tool_keyword = /IDSyscall\.sln/ nocase ascii wide
                        $string8_HadesLdr_offensive_tool_keyword = /IDSyscall\.vcxproj/ nocase ascii wide
                        $string9_HadesLdr_offensive_tool_keyword = "IDSyscall/IDSyscall" nocase ascii wide
                        $string10_HadesLdr_offensive_tool_keyword = /IDSyscall\\IDSyscall/ nocase ascii wide
                        $string11_HadesLdr_offensive_tool_keyword = /python3\sGetHash\.py\sNtCreateFile/ nocase ascii wide
                        $string12_HadesLdr_offensive_tool_keyword = /rc4\.py\s.{0,1000}\.bin/ nocase ascii wide
                        $string13_HadesLdr_offensive_tool_keyword = /syscallStuff\.asm/ nocase ascii wide
                        $string14_HadesLdr_offensive_tool_keyword = /xor\.py\s.{0,1000}\.dll/ nocase ascii wide

    condition:
        any of them
}