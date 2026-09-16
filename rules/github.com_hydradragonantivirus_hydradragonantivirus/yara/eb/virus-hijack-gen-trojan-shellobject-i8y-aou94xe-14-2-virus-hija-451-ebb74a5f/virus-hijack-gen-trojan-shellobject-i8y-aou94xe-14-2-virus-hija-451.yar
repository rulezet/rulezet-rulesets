import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aOU94xe_14_2_Virus_Hija_451 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aOU94xe_14_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.iCZ@am59Gmh_12_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@amBwvTb_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.l0Z@a8rAQKh_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_17_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.muZ@aiy413e_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20c0fac01e8031571fe756e17921f228f30405ca054e25824e783445e7899008"
    hash2       = "b7fd173bdc2020beea3f83e140d50abab33ade237289025cee7c6f138d0310d3"
    hash3       = "80cf731333315eaa8a460250d4a6e42e205e50525928bf53bc44cbc176542743"
    hash4       = "548db6e58efa795dfb8f31a38097dcde8093540e90812d001ae7717ba10b14de"
    hash5       = "f38688c9ff4528304c566af0375f521f092bf319d410dbabe004e75a61884d81"
    hash6       = "7d5a4588b152f51c6f02a89267d58be5d0c9c625b410da5c1aa2bec742d62fac"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii
    $s2 = "osoft.com/SMI/2020/WindowsSettings\">SegmentHeap</heapType></windowsSettings></application><ms_compatibility:compatibility xmlns" ascii
    $s3 = "-b9a5-48fd50a15a9a}\"></ms_compatibility:supportedOS></ms_compatibility:application></ms_compatibility:compatibility></assembly>" ascii
    $s4 = "security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><heapType xmlns=\"http://schemas.m" ascii
    $s5 = "ty:application xmlns:ms_compatibility=\"urn:schemas-microsoft-com:compatibility.v1\"><ms_compatibility:supportedOS xmlns:ms_comp" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "ed3445bd48c8bf884ee6218cb9ade0fb" and (1 of ($x*) and all of them)
    ) or (all of them)
}