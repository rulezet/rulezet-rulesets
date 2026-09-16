rule nimbo_c2
{
    meta:
        description = "Detection patterns for the tool 'nimbo-c2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nimbo-c2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/tmp\/metadata\/na\.elf/ nocase ascii wide
                        $string2 = /\[\+\]\skeystrokes\sdump\sfrom\sagent/ nocase ascii wide
                        $string3 = /agent\/dll\.nim/ nocase ascii wide
                        $string4 = /agent\/elf\.nim/ nocase ascii wide
                        $string5 = /agent\/exe\.nim/ nocase ascii wide
                        $string6 = /beacon\.elf/ nocase ascii wide
                        $string7 = /C\:\\ProgramData\\Prefetch\\na\.exe/ nocase ascii wide
                        $string8 = "C2 Framework for villains" nocase ascii wide
                        $string9 = "download /etc/passwd"
                        $string10 = "dump_lsass" nocase ascii wide
                        $string11 = /dump_sam\(/ nocase ascii wide
                        $string12 = "exit_nimbo" nocase ascii wide
                        $string13 = "Itay Migdal" nocase ascii wide
                        $string14 = "JAB4ACAAPQAgAEcAZQB0AC0AUAByAG8AYwBlAHMAcwAgAC0AUABJAEQAIAAkAHAAaQBkACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIAAtAEUAeABwAGEAbgBkAFAAcgBvAHAAZQByAHQAeQAgAG4AYQBtAGUAOwAgACIAJABwAGkAZAAgACQAeAAuAGUAeABlACIA" nocase ascii wide
                        $string15 = "KABHAGUAdAAtAEwAbwBjAGEAbABHAHIAbwB1AHAATQBlAG0AYgBlAHIAIAAtAE4AYQBtAGUAIABBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAHMAIAB8ACAAUwBlAGwAZQBjAHQALQBPAGIAagBlAGMAdAAgAC0ARQB4AHAAYQBuAGQAUAByAG8AcABlAHIAdAB5ACAAbgBhAG0AZQApACAALQBjAG8AbgB0AGEAaQBuAHMAIABbAFMAeQBzAHQAZQBtAC4AUwBlAGMAdQByAGkAdAB5AC4AUAByAGkAbgBjAGkAcABhAGwALgBXAGkAbgBkAG8AdwBzAEkAZABlAG4AdABpAHQAeQBdADoAOgBHAGUAdABDAHUAcgByAGUAbgB0ACgAKQAuAG4AYQBtAGUA" nocase ascii wide
                        $string16 = "keylogger is already off" nocase ascii wide
                        $string17 = "keylogger stopped" nocase ascii wide
                        $string18 = "lsass comsvcs" nocase ascii wide
                        $string19 = "lsass direct" nocase ascii wide
                        $string20 = "lsass dump from agent" nocase ascii wide
                        $string21 = /lsass_.{0,1000}\.dmp/ nocase ascii wide
                        $string22 = /memfd\simplant\s.{0,1000}\.elf/ nocase ascii wide
                        $string23 = /memfd\stask\s.{0,1000}\.elf/ nocase ascii wide
                        $string24 = "nimbo_main" nocase ascii wide
                        $string25 = "nimbo_prompt_color" nocase ascii wide
                        $string26 = "nimbo_root" nocase ascii wide
                        $string27 = "Nimbo-C2 w1ll r0ck y0ur w0rld" nocase ascii wide
                        $string28 = "Nimbo-C2" nocase ascii wide
                        $string29 = /Nimbo\-C2\./ nocase ascii wide
                        $string30 = "nimbo-dependencies" nocase ascii wide
                        $string31 = /persist\srun\s.{0,1000}hkcu/ nocase ascii wide
                        $string32 = /persist\srun\s.{0,1000}hklm/ nocase ascii wide
                        $string33 = /persist\sspe\s.{0,1000}\.exe/ nocase ascii wide
                        $string34 = /pstree\.ps1/ nocase ascii wide
                        $string35 = /reg\.exe\ssave\shklm\\sam/ nocase ascii wide
                        $string36 = /reg\.exe\ssave\shklm\\security/ nocase ascii wide
                        $string37 = /reg\.exe\ssave\shklm\\system/ nocase ascii wide
                        $string38 = "RwBlAHQALQBDAG8AbQBwAHUAdABlAHIASQBuAGYAbwAgAHwAIABzAGUAbABlAGMAdAAgAC0ARQB4AHAAYQBuAGQAUAByAG8AcABlAHIAdAB5ACAAVwBpAG4AZABvAHcAcwBQAHIAbwBkAHUAYwB0AE4AYQBtAGUA" nocase ascii wide
                        $string39 = "RwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAFcAaQBuADMAMgBfAE4AZQB0AHcAbwByAGsAQQBkAGEAcAB0AGUAcgBDAG8AbgBmAGkAZwB1AHIAYQB0AGkAbwBuACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIAAtAEUAeABwAGEAbgBkAFAAcgBvAHAAZQByAHQAeQAgAEkAUABBAGQAZAByAGUAcwBzACAAfAAgAFcAaABlAHIAZQAtAE8AYgBqAGUAYwB0ACAAewAoACQAXwAgAC0AbABpAGsAZQAgACIAMQAwAC4AKgAuACoALgAqACIAKQAgAC0AbwByACAAKAAkAF8AIAAtAGwAaQBrAGUAIAAiADEAOQAyAC4AMQA2ADgALgAqAC4AKgAiACkAIAAtAG8AcgAgACgAJABfACAALQBsAGkAawBlACAAIgAxADcAMgAuADEANgA4AC4AKgAuACoAIgApAH0A" nocase ascii wide
                        $string40 = /shellc\s.{0,1000}\.bin\s/ nocase ascii wide
                        $string41 = /shellc\s.{0,1000}\.shellc\s/ nocase ascii wide
                        $string42 = "uac fodhelper " nocase ascii wide
                        $string43 = "uac sdclt " nocase ascii wide
                        $string44 = "uac_bypass" nocase ascii wide
                        $string45 = "wrap_execute_assembly" nocase ascii wide
                        $string46 = "wrap_execute_encoded_powershell" nocase ascii wide
                        $string47 = "wrap_get_clipboard" nocase ascii wide
                        $string48 = "wrap_inject_shellc" nocase ascii wide
                        $string49 = "wrap_load_memfd" nocase ascii wide
                        $string50 = "wrap_unhook_ntdll" nocase ascii wide
                        $string51 = "WwBTAHkAcwB0AGUAbQAuAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsAC4AVwBpAG4AZABvAHcAcwBJAGQAZQBuAHQAaQB0AHkAXQA6ADoARwBlAHQAQwB1AHIAcgBlAG4AdAAoACkALgBuAGEAbQBlAAoA" nocase ascii wide

    condition:
        any of them
}