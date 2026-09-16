import "pe"
rule _Trojan_Hooker_Application_InstallMon_1_1_Trojan_Hooker_Applicat_75 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Application.InstallMon_1_1.vir, Trojan.Hooker_Application.InstallMon_2.vir, Virus.Autorun_Trojan.GenericKDZ.94303.vir, Virus.Hijack_Trojan.GenericKDZ.94303.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "339b931fffc0d4118f68c98957a9a98fde162dd16527b6b00266b1332dfe041e"
    hash2       = "ce0f0ff37089dec9ee511d22542532cb4d7f7ccbc9f2e2f057af7dbe6c094d2b"
    hash3       = "76e239755989b7f8cb96c52a19305956e6e1274b7db38a2c00a4135362ed647b"
    hash4       = "298489bc1d5ebb795c7aa6e644cb35729a18d59f7971695688d741db9e70cff8"

  strings:
    $s1 = "*** PFRAME bf: head=%i tail=%i   queue: head=%i tail=%i size=%i" fullword ascii
    $s2 = "*** IFRAME bf: head=%i tail=%i   queue: head=%i tail=%i size=%i" fullword ascii
    $s3 = "*** BFRAME (flush) bf: head=%i tail=%i   queue: head=%i tail=%i size=%i" fullword ascii
    $s4 = "*** BFRAME (store) bf: head=%i tail=%i   queue: head=%i tail=%i size=%i  quant=%i" fullword ascii
    $s5 = "*** FINISH bf: head=%i tail=%i   queue: head=%i tail=%i size=%i" fullword ascii
    $s6 = "*** EMPTY bf: head=%i tail=%i   queue: head=%i tail=%i size=%i" fullword ascii
    $s7 = "*** XXXXXX bf: head=%i tail=%i   queue: head=%i tail=%i size=%i" fullword ascii
    $s8 = "libjpeg-turbo version 1.5.90 (build 20180610)" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "eeac73be37480fd144f387e3563a0f14" and (all of them)
    ) or (all of them)
}