import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_lyZ_am90FFp_1_1_Virus_Hijac_148 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.lyZ@am90FFp_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.lyZ@am90FFp_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b8feb11dab3b9cb1eb2b9e966e325869a0c7010ab8ade0507559fb111b3fc76"
    hash2       = "83e502e80155a84f00827157d2d240c84f98bba985ef20539badcdb89ec205ac"

  strings:
    $s1  = "COM Port Terminal" fullword wide
    $s2  = "No COM ports found. Please attach a COM-port device." fullword wide
    $s3  = "Close COM Port" fullword wide
    $s4  = "Open COM Port" fullword wide
    $s5  = "COM port(s) found." fullword wide
    $s6  = "Open COM port on startup" fullword wide
    $s7  = "The Computer has" fullword wide
    $s8  = "Write operation began: " fullword wide
    $s9  = "Write operation succeeded: " fullword wide
    $s10 = "Welcome to the game of Nim!" fullword wide
    $s11 = "You and your opponent, the computer AI, will each take turns removing a specified number of sticks" fullword wide
    $s12 = "Sorry, the computer has beaten you. Better luck next time!" fullword wide
    $s13 = "You, the user, will go first." fullword wide
    $s14 = "The computer will go first." fullword wide
    $s15 = "Framing error." fullword wide
    $s16 = "Character buffer overrun." fullword wide
    $s17 = "Parity error." fullword wide
    $s18 = "The system is now in checkout mode. To exist checkout mode, press OK." fullword wide
    $s19 = "1Demonstrates communications between two COM ports" fullword ascii
    $s20 = "Demonstrates communications between two COM ports" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (8 of them)
    ) or (all of them)
}