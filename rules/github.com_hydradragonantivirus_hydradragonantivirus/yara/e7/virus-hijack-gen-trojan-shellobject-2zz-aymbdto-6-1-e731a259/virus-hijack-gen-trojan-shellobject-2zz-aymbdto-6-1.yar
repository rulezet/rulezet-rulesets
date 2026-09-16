rule Virus_Hijack_Gen_Trojan_ShellObject_2zZ_ayMBdto_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.2zZ@ayMBdto_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e57c4cf239bb17aa7bbdbea451ed5e4b004c0ac9d605d39a47130802b73df98"

  strings:
    $s1 = "r\"7xep1tc\"=yqm&zvv=xy\" x7t1e~d-7nm!e7k0ryv=cn,TUrd;er\"'~pl=yp\"=y;\"${rc'r7a;yqk&z7v<vc\"-xb\"5er\" " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}