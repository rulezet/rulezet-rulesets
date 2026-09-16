rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_amCvSwc_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@amCvSwc_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "014431ea5bc90782982502fee4e348e59388bd199fc70aa020312a7d8af99d48"

  strings:
    $s1 = "Getting Windows build from registry" fullword wide
    $s2 = "Determining Windows version" fullword wide
    $s3 = "Trying to load SPP based on Windows version" fullword wide
    $s4 = "Spp loading result" fullword wide
    $s5 = "RichM-" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}