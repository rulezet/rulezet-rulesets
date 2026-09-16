rule WheresMyImplant
{
    meta:
        description = "Detection patterns for the tool 'WheresMyImplant' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WheresMyImplant"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/C2\/Beacon\/.{0,1000}\.cs/ nocase ascii wide
                        $string2 = "/Inject/Dll/LoadDll" nocase ascii wide
                        $string3 = /\/Inject\/PE\/.{0,1000}\.cs/ nocase ascii wide
                        $string4 = /\/Inject\/ShellCode\/.{0,1000}\.cs/ nocase ascii wide
                        $string5 = /\/KeyLogger\.cs/ nocase ascii wide
                        $string6 = /\/Lateral\/SMB\.cs/ nocase ascii wide
                        $string7 = /\/LoadDllRemote\.cs/ nocase ascii wide
                        $string8 = /\/PE\/InjectPE\.cs/ nocase ascii wide
                        $string9 = /\/Persistence\/InstallUtil\./ nocase ascii wide
                        $string10 = "/WheresMyImplant/" nocase ascii wide
                        $string11 = /\\WheresMyImplant/ nocase ascii wide
                        $string12 = "0xbadjuju/WheresMyImplant" nocase ascii wide
                        $string13 = /Collection\/MiniDumpWriteDump\./ nocase ascii wide
                        $string14 = /Credentials\/CacheDump\./ nocase ascii wide
                        $string15 = /Credentials\/LSASecrets\./ nocase ascii wide
                        $string16 = "DumpBrowserHistory" nocase ascii wide
                        $string17 = /Empire\.Agent\.Coms\./ nocase ascii wide
                        $string18 = /Empire\.Agent\.cs/ nocase ascii wide
                        $string19 = /Empire\.Agent\.Jobs\.cs/ nocase ascii wide
                        $string20 = /Empire\.Agent\.Stager\./ nocase ascii wide
                        $string21 = /InjectPERemote\.cs/ nocase ascii wide
                        $string22 = "InjectPEWMIFSRemote" nocase ascii wide
                        $string23 = /InjectShellCode\.cs/ nocase ascii wide
                        $string24 = /InjectShellCodeRemote\.cs/ nocase ascii wide
                        $string25 = "InjectShellCodeWMIFSB64" nocase ascii wide
                        $string26 = /Lateral\/DCom\.cs/ nocase ascii wide
                        $string27 = /Lateral\/PSExec\.cs/ nocase ascii wide
                        $string28 = /Lateral\/SMBClient\.cs/ nocase ascii wide
                        $string29 = /Lateral\/SMBClientDelete\.cs/ nocase ascii wide
                        $string30 = /Lateral\/SMBClientGet\.cs/ nocase ascii wide
                        $string31 = /Lateral\/SMBClientPut\.cs/ nocase ascii wide
                        $string32 = /Lateral\/WMIExec\.cs/ nocase ascii wide
                        $string33 = "namespace WheresMyImplant" nocase ascii wide
                        $string34 = "Persistence/InstallWMI" nocase ascii wide
                        $string35 = "PTHSMBClientDelete" nocase ascii wide
                        $string36 = "PTHSMBClientGet" nocase ascii wide
                        $string37 = "PTHSMBClientList" nocase ascii wide
                        $string38 = "PTHSMBClientPut" nocase ascii wide
                        $string39 = "PTHSMBExec" nocase ascii wide
                        $string40 = "PTHWMIExec" nocase ascii wide
                        $string41 = /root\\cimv2\:Win32_Implant/ nocase ascii wide
                        $string42 = "StartWebServiceBeacon" nocase ascii wide
                        $string43 = /WheresMyImplant\.cs/ nocase ascii wide
                        $string44 = /WheresMyImplant\.git/ nocase ascii wide
                        $string45 = /WheresMyImplant\.sln/ nocase ascii wide

    condition:
        any of them
}