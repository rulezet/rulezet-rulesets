rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aa9T7Ob_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aa9T7Ob_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8496aba8ce00a5e690ab2e2cf9cb4f1f8ba93f95b6cc37e499a54dc38ce3d9d"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = " Install System v2.34</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii
    $s3 = "Height(L" fullword ascii
    $s4 = "Checked$M" fullword ascii
    $s5 = "Error Creating Allocator" fullword ascii
    $s6 = "Name<:" fullword ascii
    $s7 = "Not Find." fullword ascii
    $s8 = "Allocator class not set." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}