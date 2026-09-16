import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_m8Z_aGAMRTl_1_1_Virus_Hijac_172 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aGAMRTl_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aGAMRTl_3_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aGAMRTl_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1f7db1eab121506b2e4ed00dbf212e7a2ec00b2f9695b18a7ae70316ce62734"
    hash2       = "2a32809e1def27354de0e95abe4670638ac8abf85c0b3d15e7530d4c8e03a535"
    hash3       = "5d4da67c3d56430a3827897a69abae1dfaea9a104f1d1a4addff25b32f472681"

  strings:
    $s1  = "vncservice.cpp : SelectDesktop failed to close desktop" fullword ascii
    $s2  = "vncservice.cpp : OpenInputdesktop2 NULL" fullword ascii
    $s3  = "System Validation Report" fullword wide
    $s4  = "GetProperty(propertyId,&value)" fullword wide
    $s5  = "failed due to transient error, will retry later" fullword wide
    $s6  = "Tokenizer is a tool that uses regular expressions to split given string into tokens." fullword wide
    $s7  = "Runtime error   " fullword ascii
    $s8  = " <- memory overwrite or call to dead object detected" fullword ascii
    $s9  = "Gliders & rocking chairs" fullword ascii
    $s10 = "Player Killer of the Week" fullword ascii
    $s11 = "UPDATE [" fullword wide
    $s12 = "] INNER JOIN " fullword wide
    $s13 = "(*ppNewInstance)->Initialize( ctl::Inspectable::as_iunknown(*ppNewInstance), pPropertyViewModelInfo, pSource, propertyModelOptio" wide
    $s14 = "client-move/server-move, noop" fullword wide
    $s15 = "client-move/server-add, trying auto-rename" fullword wide
    $s16 = "client-added OneNote stub, skipping" fullword wide
    $s17 = "server-added OneNote stub" fullword wide
    $s18 = "move|rename is in progress, treating as add" fullword wide
    $s19 = "found by ServerFileID in DirMon" fullword wide
    $s20 = "Tokinizer Foundation" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "7bc7c0db4f15680cac7938d3ff5e12eb" and (8 of them)
    ) or (all of them)
}