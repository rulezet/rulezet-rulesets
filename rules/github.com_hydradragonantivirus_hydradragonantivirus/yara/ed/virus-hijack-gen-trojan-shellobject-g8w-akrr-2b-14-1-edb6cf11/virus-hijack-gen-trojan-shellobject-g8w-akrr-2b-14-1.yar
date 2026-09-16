rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aKrr_2b_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aKrr!2b_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02530d7b104f2bca51e1a37c2388877e75da1b58cd41094e0a0a0079f545dc3f"

  strings:
    $s1 = "Set IP_HDRINCL Error!" fullword ascii
    $s2 = "InitWSAStartup Error!" fullword ascii
    $s3 = "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, application/vnd.ms-excel, applicatio" ascii
    $s4 = "Send err!" fullword ascii
    $s5 = "sock err!" fullword ascii
    $s6 = "time err!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}