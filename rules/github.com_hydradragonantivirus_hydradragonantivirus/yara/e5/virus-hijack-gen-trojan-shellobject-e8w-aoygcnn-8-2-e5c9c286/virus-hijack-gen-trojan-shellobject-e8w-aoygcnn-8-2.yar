rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aOygCnn_8_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_8_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a74c3da1e601731a252173aa4c76c17263e812a6e21c565baf4b6ca808c87b9"

  strings:
    $s1 = "set cdaudio door closed" fullword wide
    $s2 = "schtasks /create /sc minute /mo 1 /tn Server /tr " fullword wide
    $s3 = "Njrat 0.7 Golden By Hassan Amiri" fullword wide
    $s4 = "Java update" fullword wide
    $s5 = "No Antivirus" fullword wide
    $s6 = "Hassan firewall delete allowedprogram \"" fullword wide
    $s7 = "[shift]" fullword wide
    $s8 = "[pause]" fullword wide
    $s9 = "[home]" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}