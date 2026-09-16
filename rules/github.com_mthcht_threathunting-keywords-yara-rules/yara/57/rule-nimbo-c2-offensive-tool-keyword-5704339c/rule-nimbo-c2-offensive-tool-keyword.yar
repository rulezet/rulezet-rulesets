rule rule_nimbo_c2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nimbo-c2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nimbo-c2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nimbo_c2_offensive_tool_keyword = /\/tmp\/metadata\/na\.elf/ nocase ascii wide
                        $string2_nimbo_c2_offensive_tool_keyword = /\[\+\]\skeystrokes\sdump\sfrom\sagent/ nocase ascii wide
                        $string3_nimbo_c2_offensive_tool_keyword = /agent\/dll\.nim/ nocase ascii wide
                        $string4_nimbo_c2_offensive_tool_keyword = /agent\/elf\.nim/ nocase ascii wide
                        $string5_nimbo_c2_offensive_tool_keyword = /agent\/exe\.nim/ nocase ascii wide
                        $string6_nimbo_c2_offensive_tool_keyword = /beacon\.elf/ nocase ascii wide
                        $string7_nimbo_c2_offensive_tool_keyword = /C\:\\ProgramData\\Prefetch\\na\.exe/ nocase ascii wide
                        $string8_nimbo_c2_offensive_tool_keyword = "C2 Framework for villains" nocase ascii wide
                        $string9_nimbo_c2_offensive_tool_keyword = "download /etc/passwd"
                        $string10_nimbo_c2_offensive_tool_keyword = "dump_lsass" nocase ascii wide
                        $string11_nimbo_c2_offensive_tool_keyword = /dump_sam\(/ nocase ascii wide
                        $string12_nimbo_c2_offensive_tool_keyword = "exit_nimbo" nocase ascii wide
                        $string13_nimbo_c2_offensive_tool_keyword = "Itay Migdal" nocase ascii wide
                        $string14_nimbo_c2_offensive_tool_keyword = "JAB4ACAAPQAgAEcAZQB0AC0AUAByAG8AYwBlAHMAcwAgAC0AUABJAEQAIAAkAHAAaQBkACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIAAtAEUAeABwAGEAbgBkAFAAcgBvAHAAZQByAHQAeQAgAG4AYQBtAGUAOwAgACIAJABwAGkAZAAgACQAeAAuAGUAeABlACIA" nocase ascii wide
                        $string15_nimbo_c2_offensive_tool_keyword = "KABHAGUAdAAtAEwAbwBjAGEAbABHAHIAbwB1AHAATQBlAG0AYgBlAHIAIAAtAE4AYQBtAGUAIABBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAHMAIAB8ACAAUwBlAGwAZQBjAHQALQBPAGIAagBlAGMAdAAgAC0ARQB4AHAAYQBuAGQAUAByAG8AcABlAHIAdAB5ACAAbgBhAG0AZQApACAALQBjAG8AbgB0AGEAaQBuAHMAIABbAFMAeQBzAHQAZQBtAC4AUwBlAGMAdQByAGkAdAB5AC4AUAByAGkAbgBjAGkAcABhAGwALgBXAGkAbgBkAG8AdwBzAEkAZABlAG4AdABpAHQAeQBdADoAOgBHAGUAdABDAHUAcgByAGUAbgB0ACgAKQAuAG4AYQBtAGUA" nocase ascii wide
                        $string16_nimbo_c2_offensive_tool_keyword = "keylogger is already off" nocase ascii wide
                        $string17_nimbo_c2_offensive_tool_keyword = "keylogger stopped" nocase ascii wide
                        $string18_nimbo_c2_offensive_tool_keyword = "lsass comsvcs" nocase ascii wide
                        $string19_nimbo_c2_offensive_tool_keyword = "lsass direct" nocase ascii wide
                        $string20_nimbo_c2_offensive_tool_keyword = "lsass dump from agent" nocase ascii wide
                        $string21_nimbo_c2_offensive_tool_keyword = /lsass_.{0,100}\.dmp/ nocase ascii wide
                        $string22_nimbo_c2_offensive_tool_keyword = /memfd\simplant\s.{0,100}\.elf/ nocase ascii wide
                        $string23_nimbo_c2_offensive_tool_keyword = /memfd\stask\s.{0,100}\.elf/ nocase ascii wide
                        $string24_nimbo_c2_offensive_tool_keyword = "nimbo_main" nocase ascii wide
                        $string25_nimbo_c2_offensive_tool_keyword = "nimbo_prompt_color" nocase ascii wide
                        $string26_nimbo_c2_offensive_tool_keyword = "nimbo_root" nocase ascii wide
                        $string27_nimbo_c2_offensive_tool_keyword = "Nimbo-C2 w1ll r0ck y0ur w0rld" nocase ascii wide
                        $string28_nimbo_c2_offensive_tool_keyword = "Nimbo-C2" nocase ascii wide
                        $string29_nimbo_c2_offensive_tool_keyword = /Nimbo\-C2\./ nocase ascii wide
                        $string30_nimbo_c2_offensive_tool_keyword = "nimbo-dependencies" nocase ascii wide
                        $string31_nimbo_c2_offensive_tool_keyword = /persist\srun\s.{0,100}hkcu/ nocase ascii wide
                        $string32_nimbo_c2_offensive_tool_keyword = /persist\srun\s.{0,100}hklm/ nocase ascii wide
                        $string33_nimbo_c2_offensive_tool_keyword = /persist\sspe\s.{0,100}\.exe/ nocase ascii wide
                        $string34_nimbo_c2_offensive_tool_keyword = /pstree\.ps1/ nocase ascii wide
                        $string35_nimbo_c2_offensive_tool_keyword = /reg\.exe\ssave\shklm\\sam/ nocase ascii wide
                        $string36_nimbo_c2_offensive_tool_keyword = /reg\.exe\ssave\shklm\\security/ nocase ascii wide
                        $string37_nimbo_c2_offensive_tool_keyword = /reg\.exe\ssave\shklm\\system/ nocase ascii wide
                        $string38_nimbo_c2_offensive_tool_keyword = "RwBlAHQALQBDAG8AbQBwAHUAdABlAHIASQBuAGYAbwAgAHwAIABzAGUAbABlAGMAdAAgAC0ARQB4AHAAYQBuAGQAUAByAG8AcABlAHIAdAB5ACAAVwBpAG4AZABvAHcAcwBQAHIAbwBkAHUAYwB0AE4AYQBtAGUA" nocase ascii wide
                        $string39_nimbo_c2_offensive_tool_keyword = "RwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAFcAaQBuADMAMgBfAE4AZQB0AHcAbwByAGsAQQBkAGEAcAB0AGUAcgBDAG8AbgBmAGkAZwB1AHIAYQB0AGkAbwBuACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIAAtAEUAeABwAGEAbgBkAFAAcgBvAHAAZQByAHQAeQAgAEkAUABBAGQAZAByAGUAcwBzACAAfAAgAFcAaABlAHIAZQAtAE8AYgBqAGUAYwB0ACAAewAoACQAXwAgAC0AbABpAGsAZQAgACIAMQAwAC4AKgAuACoALgAqACIAKQAgAC0AbwByACAAKAAkAF8AIAAtAGwAaQBrAGUAIAAiADEAOQAyAC4AMQA2ADgALgAqAC4AKgAiACkAIAAtAG8AcgAgACgAJABfACAALQBsAGkAawBlACAAIgAxADcAMgAuADEANgA4AC4AKgAuACoAIgApAH0A" nocase ascii wide
                        $string40_nimbo_c2_offensive_tool_keyword = /shellc\s.{0,100}\.bin\s/ nocase ascii wide
                        $string41_nimbo_c2_offensive_tool_keyword = /shellc\s.{0,100}\.shellc\s/ nocase ascii wide
                        $string42_nimbo_c2_offensive_tool_keyword = "uac fodhelper " nocase ascii wide
                        $string43_nimbo_c2_offensive_tool_keyword = "uac sdclt " nocase ascii wide
                        $string44_nimbo_c2_offensive_tool_keyword = "uac_bypass" nocase ascii wide
                        $string45_nimbo_c2_offensive_tool_keyword = "wrap_execute_assembly" nocase ascii wide
                        $string46_nimbo_c2_offensive_tool_keyword = "wrap_execute_encoded_powershell" nocase ascii wide
                        $string47_nimbo_c2_offensive_tool_keyword = "wrap_get_clipboard" nocase ascii wide
                        $string48_nimbo_c2_offensive_tool_keyword = "wrap_inject_shellc" nocase ascii wide
                        $string49_nimbo_c2_offensive_tool_keyword = "wrap_load_memfd" nocase ascii wide
                        $string50_nimbo_c2_offensive_tool_keyword = "wrap_unhook_ntdll" nocase ascii wide
                        $string51_nimbo_c2_offensive_tool_keyword = "WwBTAHkAcwB0AGUAbQAuAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsAC4AVwBpAG4AZABvAHcAcwBJAGQAZQBuAHQAaQB0AHkAXQA6ADoARwBlAHQAQwB1AHIAcgBlAG4AdAAoACkALgBuAGEAbQBlAAoA" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}