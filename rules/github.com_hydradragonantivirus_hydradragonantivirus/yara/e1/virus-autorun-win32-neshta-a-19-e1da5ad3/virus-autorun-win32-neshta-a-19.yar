rule Virus_Autorun_Win32_Neshta_A_19 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f52717940b102c9d5f5f1110b4b1eed12a01049082e4a13d3b3fef452a7f3cf"

  strings:
    $x1  = "PA<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity " ascii
    $s2  = "evel level=\"asInvoker\" uiAccess=\"false\"></ms_asmv2:requestedExecutionLevel></ms_asmv2:requestedPrivileges></ms_asmv2:securit" ascii
    $s3  = "xmlns:ms_asmv2=\"urn:schemas-microsoft-com:asm.v2\"><ms_asmv2:security><ms_asmv2:requestedPrivileges><ms_asmv2:requestedExecutio" ascii
    $s4  = "autoRun, Version 1.0" fullword wide
    $s5  = "string_t:version_1:adobe" fullword ascii
    $s6  = "About autoRun" fullword wide
    $s7  = "PA<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity " ascii
    $s8  = "?read_request@flash_external_interface@owl_canvas@adobe@@YA?AUrequest_t@version_0@123@PBDK@Z" fullword ascii
    $s9  = "unicode: utf16 high surrogate found without low surrogate" fullword ascii
    $s10 = "unicode: utf16 low surrogate found without high surrogate" fullword ascii
    $s11 = " Creative Suite" fullword wide
    $s12 = "?flash_player_invoke_request@flash_external_interface@owl_canvas@adobe@@YA?AVany_regular_t@version_1@3@PAUHWND__@@ABUrequest_t@v" ascii
    $s13 = "?flash_player_invoke_request@flash_external_interface@owl_canvas@adobe@@YA?AVany_regular_t@version_1@3@PAUHWND__@@ABUrequest_t@v" ascii
    $s14 = ".?AVbad_cast@adobe@@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}