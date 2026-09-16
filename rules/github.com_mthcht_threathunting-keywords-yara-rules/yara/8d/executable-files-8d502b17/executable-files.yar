rule Executable_Files
{
    meta:
        description = "Detection patterns for the tool 'Executable_Files' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Executable_Files"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sexfiltrate\.exe/ nocase ascii wide
                        $string2 = /\/Executable_Files\.git/ nocase ascii wide
                        $string3 = /\/exfiltrate\.exe/ nocase ascii wide
                        $string4 = /\/Hades\.exe/ nocase ascii wide
                        $string5 = /\/Rubeus\.exe/ nocase ascii wide
                        $string6 = "/XOR_b64_encrypted/" nocase ascii wide
                        $string7 = /\\exfiltrate\.exe/ nocase ascii wide
                        $string8 = /\\Hades\.exe/ nocase ascii wide
                        $string9 = /\\Rubeus\.exe/ nocase ascii wide
                        $string10 = /\\XOR_b64_encrypted\\/ nocase ascii wide
                        $string11 = /\\xorencrypt\.py/ nocase ascii wide
                        $string12 = /badger_x64_stealth_rtl\.txt/ nocase ascii wide
                        $string13 = /cpp_test_payload\.exe/ nocase ascii wide
                        $string14 = /Executable_Files\-main\.zip/ nocase ascii wide
                        $string15 = /exfiltrate_via_post\.exe/ nocase ascii wide
                        $string16 = /HelloReflectionWorld\.exe/ nocase ascii wide
                        $string17 = /https_revshell\.exe/ nocase ascii wide
                        $string18 = /mimikatz\.exe/ nocase ascii wide
                        $string19 = /mssgbox_shellcode_arranged_x64\.b64/ nocase ascii wide
                        $string20 = /mssgbox_shellcode_exitfunc_thread_x64\.bin/ nocase ascii wide
                        $string21 = /mssgbox_shellcode_x64\.b64/ nocase ascii wide
                        $string22 = /mssgbox_shellcode_x64\.bin/ nocase ascii wide
                        $string23 = /mssgbox_shellcode_x64\.bin/ nocase ascii wide
                        $string24 = /mssgbox_shellcode_x64_with_hexsymbol\.txt/ nocase ascii wide
                        $string25 = /mssgbox_shellcode_x64_without_hexsymbol\.txt/ nocase ascii wide
                        $string26 = /RegistryTinker\.exe/ nocase ascii wide
                        $string27 = "rev_kali_192_168_0_110_1234" nocase ascii wide
                        $string28 = "reveng007/Executable_Files" nocase ascii wide
                        $string29 = /Rubeus\.exe\s/ nocase ascii wide
                        $string30 = /SafetyKatz\.exe/ nocase ascii wide
                        $string31 = /win_rev_http\.exe/ nocase ascii wide
                        $string32 = /win_rev_https\.exe/ nocase ascii wide
                        $string33 = /win_rev_tcp\.exe/ nocase ascii wide
                        $string34 = /XOR_b64_encrypted.{0,1000}covenant\.txt/ nocase ascii wide
                        $string35 = /XOR_b64_encrypted.{0,1000}covenant2\.txt/ nocase ascii wide
                        $string36 = /XOR_b64_encrypted.{0,1000}havoc\.txt/ nocase ascii wide

    condition:
        any of them
}