rule rule_ReflectiveNtdll_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ReflectiveNtdll' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ReflectiveNtdll"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ReflectiveNtdll_offensive_tool_keyword = /\/enc_shellcode\.bin/ nocase ascii wide
                        $string2_ReflectiveNtdll_offensive_tool_keyword = /\/enc_shellcode\.h/ nocase ascii wide
                        $string3_ReflectiveNtdll_offensive_tool_keyword = /\/ReflectiveNtdll\.git/ nocase ascii wide
                        $string4_ReflectiveNtdll_offensive_tool_keyword = /\\1\.Encrypt_shellcode/ nocase ascii wide
                        $string5_ReflectiveNtdll_offensive_tool_keyword = /\\enc_shellcode\.bin/ nocase ascii wide
                        $string6_ReflectiveNtdll_offensive_tool_keyword = /\\enc_shellcode\.h/ nocase ascii wide
                        $string7_ReflectiveNtdll_offensive_tool_keyword = /\\implant\.exe\s.{0,1000}\.exe/ nocase ascii wide
                        $string8_ReflectiveNtdll_offensive_tool_keyword = /POC1.{0,1000}implant\.cpp/ nocase ascii wide
                        $string9_ReflectiveNtdll_offensive_tool_keyword = /POC2.{0,1000}implant\.cpp/ nocase ascii wide
                        $string10_ReflectiveNtdll_offensive_tool_keyword = "ReflectiveNtdll-main" nocase ascii wide
                        $string11_ReflectiveNtdll_offensive_tool_keyword = "reveng007/ReflectiveNtdll" nocase ascii wide

    condition:
        any of them
}