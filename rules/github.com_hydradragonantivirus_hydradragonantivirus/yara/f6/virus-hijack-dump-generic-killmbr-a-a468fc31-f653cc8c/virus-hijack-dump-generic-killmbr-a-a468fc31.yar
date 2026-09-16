rule Virus_Hijack_Dump_Generic_KillMBR_A_A468FC31 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dump.Generic.KillMBR.A.A468FC31.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d041533a41d49d4a87f54449c95b140d8d4153b46889a14fe63a9d96b08e8df4"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}