rule Virus_Hijack_Backdoor_Hangup_B_292 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_292.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b50ac98e7cf74e3b715d458b25470172adb0333d77ede359b9469af42416c667"

  strings:
    $s1 = "MA. Agreement Definitions" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}