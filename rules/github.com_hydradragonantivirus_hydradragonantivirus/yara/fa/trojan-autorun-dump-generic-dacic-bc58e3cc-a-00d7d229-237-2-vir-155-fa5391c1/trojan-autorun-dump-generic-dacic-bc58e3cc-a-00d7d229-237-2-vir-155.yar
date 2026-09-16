import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_237_2_Vir_155 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_237_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_17_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_18_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_25_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f9c0eb9c4b24dab687e7d0bbde4964aaa92860d01cd925db182356e5a4052d3"
    hash2       = "5f4e08ff55f9130c843fb3251856a8bbf945f615050a51fdc667ca113fb2e867"
    hash3       = "db69f180a89ec5a7f02fc09b425f574c2ec1f8d06c7d3103fc5531112c99b971"
    hash4       = "ad83f4a4563b94420182654f956f45c6555d88c4fb0392dbe73df0eeafbdfc17"
    hash5       = "94d7211ffde81b151fc2398949697f2e8388f2a4a11f01209432208ef34718a2"

  strings:
    $s1 = " Remove %Windir%\\SoftwareDistribution" fullword ascii
    $s2 = " defrag -V (Windows Vista)" fullword ascii
    $s3 = "Optimize System Drive:" fullword ascii
    $s4 = "System File Checker:" fullword ascii
    $s5 = "Windows Health Check:" fullword ascii
    $s6 = "?Performs various tasks to refresh the overall health of Windows" fullword ascii
    $s7 = "Windows Health Check" fullword ascii
    $s8 = "Charlie Dobson" fullword ascii
    $s9 = "Clear Cached Updates:" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (all of them)
    ) or (all of them)
}