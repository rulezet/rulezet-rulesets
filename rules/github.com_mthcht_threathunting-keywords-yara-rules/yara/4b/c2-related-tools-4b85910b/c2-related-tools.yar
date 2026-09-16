rule C2_related_tools
{
    meta:
        description = "Detection patterns for the tool 'C2 related tools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2 related tools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sbeacon64\.bin\s/ nocase ascii wide
                        $string2 = /\sNoPowerShell\./ nocase ascii wide
                        $string3 = /\s\-pe\-exp\-list\s.{0,1000}\.dll/ nocase ascii wide
                        $string4 = /\ssigflip\./ nocase ascii wide
                        $string5 = " -U msf -P msf " nocase ascii wide
                        $string6 = /\!wPkgPath\!.{0,1000}\!ak\!/ nocase ascii wide
                        $string7 = "/bypass_mod/loader" nocase ascii wide
                        $string8 = "/Cooolis-ms/" nocase ascii wide
                        $string9 = /\/DllExport\.bat/ nocase ascii wide
                        $string10 = "/nopowershell/" nocase ascii wide
                        $string11 = "/ShellcodeFluctuation" nocase ascii wide
                        $string12 = /\/SigFlip\./ nocase ascii wide
                        $string13 = "/SigFlip/" nocase ascii wide
                        $string14 = "/SigLoader/" nocase ascii wide
                        $string15 = "/unhook-bof" nocase ascii wide
                        $string16 = /\\codeloader\.exe/ nocase ascii wide
                        $string17 = /\\Cooolis\-ms\-Loader\\/ nocase ascii wide
                        $string18 = /\\DllExport\.bat/ nocase ascii wide
                        $string19 = /\\NoPowerShell\./ nocase ascii wide
                        $string20 = /\\tests\\beacon64\.bin/ nocase ascii wide
                        $string21 = /APC_Ijnect_Load\.nim/ nocase ascii wide
                        $string22 = /BOFNET\.dll/ nocase ascii wide
                        $string23 = /bofnet_execute\./ nocase ascii wide
                        $string24 = "bWV0YXNwbG9pdA==" nocase ascii wide
                        $string25 = "c2hlbGxjb2Rl" nocase ascii wide
                        $string26 = "cGlwZW5hbWU9" nocase ascii wide
                        $string27 = "cmVmbGVjdGl2ZQ==" nocase ascii wide
                        $string28 = /codeLoader\/codeLoader\./ nocase ascii wide
                        $string29 = /cool.{0,1000}\/cool\.zip/ nocase ascii wide
                        $string30 = /coolv0\.1\.exe/ nocase ascii wide
                        $string31 = /Cooolis.{0,1000}shellcode/ nocase ascii wide
                        $string32 = "CooolisAdjustTokenPrivileges" nocase ascii wide
                        $string33 = "CooolisCreateRemoteThread" nocase ascii wide
                        $string34 = "Cooolis-ExternalC2" nocase ascii wide
                        $string35 = /Cooolis\-ms\.exe/ nocase ascii wide
                        $string36 = "Cooolis-msf" nocase ascii wide
                        $string37 = /Cooolis\-msX64\.zip/ nocase ascii wide
                        $string38 = /Cooolis\-msX86\.zip/ nocase ascii wide
                        $string39 = "Cooolis-Reflective" nocase ascii wide
                        $string40 = "Cooolis-Shellcode" nocase ascii wide
                        $string41 = /Cooolis\-String\./ nocase ascii wide
                        $string42 = "CooolisVirtualAlloc" nocase ascii wide
                        $string43 = "DllExport -" nocase ascii wide
                        $string44 = "Ed1s0nZ/cool/" nocase ascii wide
                        $string45 = /execute\-assembly.{0,1000}sigflip/ nocase ascii wide
                        $string46 = /g_hookedSleep\./ nocase ascii wide
                        $string47 = "GetWhoamiCommand" nocase ascii wide
                        $string48 = "IERMTCBpbnRvIHByb2Nlc3MgOiA=" nocase ascii wide
                        $string49 = "initializeShellcodeFluctuation" nocase ascii wide
                        $string50 = "injectShellcode" nocase ascii wide
                        $string51 = "isShellcodeThread" nocase ascii wide
                        $string52 = "LUgsLS1IT1NU" nocase ascii wide
                        $string53 = "LVAsLS1QT1JU" nocase ascii wide
                        $string54 = "LW8sLS1vcHRpb25z" nocase ascii wide
                        $string55 = "LWIsLS1idWNrZXQ=" nocase ascii wide
                        $string56 = "LWYsLS1maWxl" nocase ascii wide
                        $string57 = "LXAsLS1waWQ=" nocase ascii wide
                        $string58 = "LXAsLS1wYXlsb2Fk" nocase ascii wide
                        $string59 = "LXUsLS11cmk=" nocase ascii wide
                        $string60 = "med0x2e/SigFlip" nocase ascii wide
                        $string61 = "NimShellCodeLoader" nocase ascii wide
                        $string62 = /NoPowerShell\.cna/ nocase ascii wide
                        $string63 = /NoPowerShell\.dll/ nocase ascii wide
                        $string64 = /nopowershell\.exe/ nocase ascii wide
                        $string65 = /NoPowerShell\/.{0,1000}\.cs/ nocase ascii wide
                        $string66 = "nps whoami" nocase ascii wide
                        $string67 = "OEP_Hiijack_Inject_Load" nocase ascii wide
                        $string68 = "Q29iYWx0IFN0cmlrZSBFeHRlcm5hbCBDMiBMb2FkZXI=" nocase ascii wide
                        $string69 = "readShellcode" nocase ascii wide
                        $string70 = "runShellcode" nocase ascii wide
                        $string71 = "Rvn0xsy/Cooolis-ms" nocase ascii wide
                        $string72 = "RXh0ZXJuYWwgQzIgUG9ydA==" nocase ascii wide
                        $string73 = "service/executable/" nocase ascii wide
                        $string74 = /service\/executable\/compile\.exe/ nocase ascii wide
                        $string75 = "shellcodeEncryptDecrypt" nocase ascii wide
                        $string76 = /ShellcodeFluctuation\./ nocase ascii wide
                        $string77 = "ShellcodeFluctuation64" nocase ascii wide
                        $string78 = "ShellcodeFluctuation86" nocase ascii wide
                        $string79 = /sigflip.{0,1000}\/Bof\// nocase ascii wide
                        $string80 = "SigInject " nocase ascii wide
                        $string81 = "SigLoader " nocase ascii wide
                        $string82 = /SigLoader\./ nocase ascii wide
                        $string83 = /src\\unhook\.c/ nocase ascii wide
                        $string84 = /Thread_Hiijack_Inject_Load\./ nocase ascii wide
                        $string85 = "ThreadStackSpoofer" nocase ascii wide
                        $string86 = "TWV0YXNwbG9pdCBSUEMgTG9hZGVy" nocase ascii wide
                        $string87 = "U2hlbGxjb2RlIFBhdGg=" nocase ascii wide
                        $string88 = "UFR5cGUgQW5kIFBPcHRpb25zIFRvbyBsb25nIQ==" nocase ascii wide
                        $string89 = "UGF5bG9hZCBOYW1lLCBlLmcuIHdpbmRvd3MvbWV0ZXJwcmV0ZXIvcmV2ZXJzZV90Y3A=" nocase ascii wide
                        $string90 = "UGF5bG9hZCBvcHRpb25zLCBlLmcuIExIT1NUPTEuMS4xLjEsTFBPUlQ9ODg2Ng==" nocase ascii wide
                        $string91 = "UlBDIFNlcnZlciBIb3N0" nocase ascii wide
                        $string92 = "UlBDIFNlcnZlciBQb3J0" nocase ascii wide
                        $string93 = "UmVmbGVjdGl2ZSBETEwgaW5qZWN0aW9u" nocase ascii wide
                        $string94 = "UmVmbGVjdGl2ZSBETEwgT1NTIEJ1Y2tldA==" nocase ascii wide
                        $string95 = "UmVmbGVjdGl2ZSBETEwgUGF0aA==" nocase ascii wide
                        $string96 = "UmVmbGVjdGl2ZSBETEwgVVJJ" nocase ascii wide
                        $string97 = "UmVmbGVjdGl2ZSBJbmplY3QgUHJvY2VzcyBJZA==" nocase ascii wide
                        $string98 = "unhook kernel32" nocase ascii wide
                        $string99 = "unhook wldp amsi" nocase ascii wide
                        $string100 = "WypdIENhbid0IENvbm5lY3QgQWxpeXVuIEJ1Y2tldC4=" nocase ascii wide
                        $string101 = "WypdIFRoZSBCdWNrZXQgb3IgUmVmbGVjdGl2ZSBETEwgVVJJIGlzIEVtcHR5Lg==" nocase ascii wide
                        $string102 = "WytdIEluamVjdGVkIHRoZSA=" nocase ascii wide
                        $string103 = "Y29iYWx0c3RyaWtl" nocase ascii wide
                        $string104 = "YmxvY2s9MTAw" nocase ascii wide

    condition:
        any of them
}