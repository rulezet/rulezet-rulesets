rule Virus_Hijack_Gen_Trojan_ShellObject_h8W_a853Pwn_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8W@a853Pwn_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2ad34af667d349fa569abb5da53e63ce870c7bc6f368c87d689bde0b85ab901"

  strings:
    $s1 = "Content-Disposition: attachment; filename=PurpleMood.scr" fullword ascii
    $s2 = "RCPT TO: <test@pact518.hit.edu.cn>" fullword ascii
    $s3 = "Subject:hi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}