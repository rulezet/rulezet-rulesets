rule HadesLdr
{
    meta:
        description = "Detection patterns for the tool 'HadesLdr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HadesLdr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-h\s.{0,1000}\-p\s.{0,1000}\s\-c\scypher\.bin\s\-k\skey\.bin/ nocase ascii wide
                        $string2 = /\/HadesLdr\.git/ nocase ascii wide
                        $string3 = /\/scripts\/xor\.py/ nocase ascii wide
                        $string4 = "CognisysGroup/HadesLdr" nocase ascii wide
                        $string5 = "HadesLdr-main" nocase ascii wide
                        $string6 = /IDSyscall\.exe/ nocase ascii wide
                        $string7 = /IDSyscall\.sln/ nocase ascii wide
                        $string8 = /IDSyscall\.vcxproj/ nocase ascii wide
                        $string9 = "IDSyscall/IDSyscall" nocase ascii wide
                        $string10 = /IDSyscall\\IDSyscall/ nocase ascii wide
                        $string11 = /python3\sGetHash\.py\sNtCreateFile/ nocase ascii wide
                        $string12 = /rc4\.py\s.{0,1000}\.bin/ nocase ascii wide
                        $string13 = /syscallStuff\.asm/ nocase ascii wide
                        $string14 = /xor\.py\s.{0,1000}\.dll/ nocase ascii wide

    condition:
        any of them
}