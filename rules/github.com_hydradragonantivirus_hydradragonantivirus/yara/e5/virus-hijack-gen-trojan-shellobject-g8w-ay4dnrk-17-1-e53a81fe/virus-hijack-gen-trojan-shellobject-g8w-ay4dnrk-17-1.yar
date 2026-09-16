rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd213ea57ccc64f8844d3c0f665d3fc5d2bb04692ed695f4991bb0a8cf4c5e00"

  strings:
    $s1 = "Unsalable" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}