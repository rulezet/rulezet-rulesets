rule rule_Executable_Files_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Executable_Files' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Executable_Files"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Executable_Files_offensive_tool_keyword = /\sexfiltrate\.exe/ nocase ascii wide
                        $string2_Executable_Files_offensive_tool_keyword = /\/Executable_Files\.git/ nocase ascii wide
                        $string3_Executable_Files_offensive_tool_keyword = /\/exfiltrate\.exe/ nocase ascii wide
                        $string4_Executable_Files_offensive_tool_keyword = /\/Hades\.exe/ nocase ascii wide
                        $string5_Executable_Files_offensive_tool_keyword = /\/Rubeus\.exe/ nocase ascii wide
                        $string6_Executable_Files_offensive_tool_keyword = "/XOR_b64_encrypted/" nocase ascii wide
                        $string7_Executable_Files_offensive_tool_keyword = /\\exfiltrate\.exe/ nocase ascii wide
                        $string8_Executable_Files_offensive_tool_keyword = /\\Hades\.exe/ nocase ascii wide
                        $string9_Executable_Files_offensive_tool_keyword = /\\Rubeus\.exe/ nocase ascii wide
                        $string10_Executable_Files_offensive_tool_keyword = /\\XOR_b64_encrypted\\/ nocase ascii wide
                        $string11_Executable_Files_offensive_tool_keyword = /\\xorencrypt\.py/ nocase ascii wide
                        $string12_Executable_Files_offensive_tool_keyword = /badger_x64_stealth_rtl\.txt/ nocase ascii wide
                        $string13_Executable_Files_offensive_tool_keyword = /cpp_test_payload\.exe/ nocase ascii wide
                        $string14_Executable_Files_offensive_tool_keyword = /Executable_Files\-main\.zip/ nocase ascii wide
                        $string15_Executable_Files_offensive_tool_keyword = /exfiltrate_via_post\.exe/ nocase ascii wide
                        $string16_Executable_Files_offensive_tool_keyword = /HelloReflectionWorld\.exe/ nocase ascii wide
                        $string17_Executable_Files_offensive_tool_keyword = /https_revshell\.exe/ nocase ascii wide
                        $string18_Executable_Files_offensive_tool_keyword = /mimikatz\.exe/ nocase ascii wide
                        $string19_Executable_Files_offensive_tool_keyword = /mssgbox_shellcode_arranged_x64\.b64/ nocase ascii wide
                        $string20_Executable_Files_offensive_tool_keyword = /mssgbox_shellcode_exitfunc_thread_x64\.bin/ nocase ascii wide
                        $string21_Executable_Files_offensive_tool_keyword = /mssgbox_shellcode_x64\.b64/ nocase ascii wide
                        $string22_Executable_Files_offensive_tool_keyword = /mssgbox_shellcode_x64\.bin/ nocase ascii wide
                        $string23_Executable_Files_offensive_tool_keyword = /mssgbox_shellcode_x64\.bin/ nocase ascii wide
                        $string24_Executable_Files_offensive_tool_keyword = /mssgbox_shellcode_x64_with_hexsymbol\.txt/ nocase ascii wide
                        $string25_Executable_Files_offensive_tool_keyword = /mssgbox_shellcode_x64_without_hexsymbol\.txt/ nocase ascii wide
                        $string26_Executable_Files_offensive_tool_keyword = /RegistryTinker\.exe/ nocase ascii wide
                        $string27_Executable_Files_offensive_tool_keyword = "rev_kali_192_168_0_110_1234" nocase ascii wide
                        $string28_Executable_Files_offensive_tool_keyword = "reveng007/Executable_Files" nocase ascii wide
                        $string29_Executable_Files_offensive_tool_keyword = /Rubeus\.exe\s/ nocase ascii wide
                        $string30_Executable_Files_offensive_tool_keyword = /SafetyKatz\.exe/ nocase ascii wide
                        $string31_Executable_Files_offensive_tool_keyword = /win_rev_http\.exe/ nocase ascii wide
                        $string32_Executable_Files_offensive_tool_keyword = /win_rev_https\.exe/ nocase ascii wide
                        $string33_Executable_Files_offensive_tool_keyword = /win_rev_tcp\.exe/ nocase ascii wide
                        $string34_Executable_Files_offensive_tool_keyword = /XOR_b64_encrypted.{0,1000}covenant\.txt/ nocase ascii wide
                        $string35_Executable_Files_offensive_tool_keyword = /XOR_b64_encrypted.{0,1000}covenant2\.txt/ nocase ascii wide
                        $string36_Executable_Files_offensive_tool_keyword = /XOR_b64_encrypted.{0,1000}havoc\.txt/ nocase ascii wide

    condition:
        any of them
}