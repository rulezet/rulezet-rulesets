rule Pezor
{
    meta:
        description = "Detection patterns for the tool 'Pezor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pezor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -64 -format=bof " nocase ascii wide
                        $string2 = " -64 -format=dll " nocase ascii wide
                        $string3 = " -64 -format=service-dll " nocase ascii wide
                        $string4 = " -fluctuate=NA -sleep=" nocase ascii wide
                        $string5 = " -fluctuate=RW -sleep=" nocase ascii wide
                        $string6 = /\s\-format\=bof\s.{0,1000}\.exe/ nocase ascii wide
                        $string7 = " -format=bof -cleanup " nocase ascii wide
                        $string8 = " -format=dotnet -sleep=" nocase ascii wide
                        $string9 = " -format=dotnet-pinvoke " nocase ascii wide
                        $string10 = /\s\-format\=dotnet\-pinvoke\s.{0,1000}\.exe/ nocase ascii wide
                        $string11 = " -format=reflective-dll " nocase ascii wide
                        $string12 = /\s\-format\=reflective\-dll\s.{0,1000}\.exe/ nocase ascii wide
                        $string13 = /\s\-format\=service\-dll\s.{0,1000}\.exe/ nocase ascii wide
                        $string14 = /\s\-format\=service\-exe\s.{0,1000}\.exe/ nocase ascii wide
                        $string15 = " kalilinux/kali-rolling"
                        $string16 = /\s\-p\s.{0,1000}\\mimi\.out/ nocase ascii wide
                        $string17 = /\sPEzor\.py\s/ nocase ascii wide
                        $string18 = /\sPEzor\.sh\s/
                        $string19 = /\sPEzor\.sh\s/
                        $string20 = " -sgn -syscalls " nocase ascii wide
                        $string21 = " -sgn -unhook -antidebug " nocase ascii wide
                        $string22 = /\s\-syscalls\s\-sleep\=.{0,1000}\.exe/ nocase ascii wide
                        $string23 = " -unhook -antidebug " nocase ascii wide
                        $string24 = /\s\-unhook\s\-antidebug\s.{0,1000}\s\-self\s\-sleep/ nocase ascii wide
                        $string25 = " -unhook -syscalls -obfuscate " nocase ascii wide
                        $string26 = /\.\/PEzor\.sh/
                        $string27 = /\.sh\s\-format\=bof\s.{0,1000}\.exe/
                        $string28 = /\.sh\s\-format\=service\-dll\s/
                        $string29 = /\.sh\s\-format\=service\-exe\s/
                        $string30 = /\.sh\s\-xorkey\=/
                        $string31 = /\/bof\.cpp\s/
                        $string32 = /\/inject\.cpp/ nocase ascii wide
                        $string33 = /\/inline_syscall\.git/ nocase ascii wide
                        $string34 = /\/inline_syscall\/include\/in_memory_init\.hpp/ nocase ascii wide
                        $string35 = /\/PEzor\.cna/ nocase ascii wide
                        $string36 = /\/PEzor\.git/ nocase ascii wide
                        $string37 = /\/PEzor\.git/ nocase ascii wide
                        $string38 = /\/PEzor\.py/
                        $string39 = /\/PEzor\.sh\s/
                        $string40 = /\/PEzor\/inject\.cpp/ nocase ascii wide
                        $string41 = /\/ReflectiveDll\.c/ nocase ascii wide
                        $string42 = "/ReflectiveDLLInjection/" nocase ascii wide
                        $string43 = /\/ReflectiveLoader\.c/ nocase ascii wide
                        $string44 = /\/shellcode\.bin\./ nocase ascii wide
                        $string45 = /\/shellcode\.hpp/ nocase ascii wide
                        $string46 = /\/system\:SystemBkup\.hiv\s\/sam\:SamBkup\.hiv/
                        $string47 = /\[PEzor\]\scleanup\scomplete/ nocase ascii wide
                        $string48 = /\[PEzor\]\spayload\sfreed/ nocase ascii wide
                        $string49 = /\[PEzor\]\sstarting\sBOF/ nocase ascii wide
                        $string50 = /\\dll\-sideload\\main\.cpp/ nocase ascii wide
                        $string51 = /\\PEzor\.cpp/ nocase ascii wide
                        $string52 = /\\PEzor\.hpp/ nocase ascii wide
                        $string53 = /\\PEzor\\loader\.c/ nocase ascii wide
                        $string54 = /\\shellcode\.hpp/ nocase ascii wide
                        $string55 = "_prefix_PEzor_" nocase ascii wide
                        $string56 = "_REFLECTIVEDLLINJECTION_" nocase ascii wide
                        $string57 = "-64 -format=reflective-dll " nocase ascii wide
                        $string58 = "cannot encode the shellcode when self-executing the payload" nocase ascii wide
                        $string59 = /Console\.WriteLine.{0,1000}self\sexecuting\sthe\spayload/ nocase ascii wide
                        $string60 = "cowsay -f dragon 'PEzor!!" nocase ascii wide
                        $string61 = /\-dll\-sideload\=.{0,1000}\.dll/ nocase ascii wide
                        $string62 = "echo 'PEzor!!" nocase ascii wide
                        $string63 = "execute_Pezor" nocase ascii wide
                        $string64 = "execute-Pezor" nocase ascii wide
                        $string65 = "-format=dotnet-createsection -sleep" nocase ascii wide
                        $string66 = "generate_raw_payload" nocase ascii wide
                        $string67 = "inject_shellcode_self" nocase ascii wide
                        $string68 = /iwantmore\.pizza\/posts\/PEzor\.html/ nocase ascii wide
                        $string69 = "PEzor generated Beacon Object File" nocase ascii wide
                        $string70 = "PEzor!! v" nocase ascii wide
                        $string71 = /PEzor.{0,1000}\/Inject\.c/ nocase ascii wide
                        $string72 = /Pezor.{0,1000}inject\.hpp/ nocase ascii wide
                        $string73 = /PEzor\.sh\s\-/
                        $string74 = /PEzor\.sh\s.{0,1000}\.bin/
                        $string75 = /PEzor\.sh\s\-32/
                        $string76 = /PEzor\.sh\s\-64/
                        $string77 = /PEzor\/.{0,1000}\/bof\.cpp/ nocase ascii wide
                        $string78 = /PEzor\/.{0,1000}syscalls\.hpp/ nocase ascii wide
                        $string79 = /PEzor\\inject\.cpp/ nocase ascii wide
                        $string80 = "phra/Pezor" nocase ascii wide
                        $string81 = "phra/Pezor/" nocase ascii wide
                        $string82 = "ReflectiveDLLInjection/dll" nocase ascii wide
                        $string83 = /shellcode\.bin\.donut/ nocase ascii wide

    condition:
        any of them
}