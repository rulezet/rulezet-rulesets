rule ReflectiveNtdll
{
    meta:
        description = "Detection patterns for the tool 'ReflectiveNtdll' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ReflectiveNtdll"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/enc_shellcode\.bin/ nocase ascii wide
                        $string2 = /\/enc_shellcode\.h/ nocase ascii wide
                        $string3 = /\/ReflectiveNtdll\.git/ nocase ascii wide
                        $string4 = /\\1\.Encrypt_shellcode/ nocase ascii wide
                        $string5 = /\\enc_shellcode\.bin/ nocase ascii wide
                        $string6 = /\\enc_shellcode\.h/ nocase ascii wide
                        $string7 = /\\implant\.exe\s.{0,1000}\.exe/ nocase ascii wide
                        $string8 = /POC1.{0,1000}implant\.cpp/ nocase ascii wide
                        $string9 = /POC2.{0,1000}implant\.cpp/ nocase ascii wide
                        $string10 = "ReflectiveNtdll-main" nocase ascii wide
                        $string11 = "reveng007/ReflectiveNtdll" nocase ascii wide

    condition:
        any of them
}