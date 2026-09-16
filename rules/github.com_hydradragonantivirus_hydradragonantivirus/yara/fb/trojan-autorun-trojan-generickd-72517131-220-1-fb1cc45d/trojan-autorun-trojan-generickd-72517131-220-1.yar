rule Trojan_Autorun_Trojan_GenericKD_72517131_220_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_220_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a66adf628d370456843ecf73e1715291d9c6a5327af9a85fcf3ff81385a2c585"

  strings:
    $s1 = "V7User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}