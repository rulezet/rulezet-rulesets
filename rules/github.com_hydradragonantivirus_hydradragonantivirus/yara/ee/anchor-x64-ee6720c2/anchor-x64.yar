import "pe"
rule anchor_x64 {
  meta:
    description = "files - file anchor_x64.exe"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-02-22"
    hash1       = "ca72600f50c76029b6fb71f65423afc44e4e2d93257c3f95fb994adc602f3e1b"

  strings:
    $x1  = "cmd.exe /c timeout 3 && " fullword wide
    $x2  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo><security><requestedPrivileges><requeste" ascii
    $x3  = "api-ms-win-core-synch-l1-2-0.dll" fullword wide  
    $s4  = "\\System32\\cmd.ex\\System32\\rundllP" fullword ascii
    $s5  = "Z:\\D\\GIT\\anchorDns.llvm\\Bin\\x64\\Release\\anchorDNS_x64.pdb" fullword ascii
    $s6  = "AppPolicyGetProcessTerminationMethod" fullword ascii
    $s7  = "cutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><appli" ascii
    $s8  = "thExecute" fullword ascii
    $s9  = "on xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSe" ascii
    $s10 = "WinHTTP loader/1.0" fullword wide
    $s11 = "AppPolicyGetThreadInitializationType" fullword ascii
    $s12 = "AnchorDNS.cpp" fullword ascii
    $s13 = "hardWorker.cpp" fullword ascii
    $s14 = "operator<=>" fullword ascii
    $s15 = "operator co_await" fullword ascii
    $s16 = "/C PowerShell \"Start-Slemove-Iteep 3; Re" fullword wide
    $s17 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo><security><requestedPrivileges><requeste" ascii
    $s18 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
    $s19 = "UAWAVAUATVWSH" fullword ascii
    $s20 = "AWAVAUATVWUSH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and
    (pe.imphash() == "e2450fb3cc5b1b7305e3193fe03f3369" and (1 of ($x*) or 8 of them))
}