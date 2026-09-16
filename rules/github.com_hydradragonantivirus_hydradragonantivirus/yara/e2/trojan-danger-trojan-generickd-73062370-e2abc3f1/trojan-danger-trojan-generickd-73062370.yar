rule Trojan_Danger_Trojan_GenericKD_73062370 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.73062370.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6d1ca104d9af7b0cab2bac0cf5214cf2ed046e168bc03bc6a5eb755680d5dcc"

  strings:
    $s1 = "simultaneously only to provide you with technical support.in50ua4b3x6r500q4o5qqk5p14i1pii562jei88vpm51h21bq0f0u6989qnm5px5951f25" ascii
    $s2 = "simultaneously only to provide you with technical support.in50ua4b3x6r500q4o5qqk5p14i1pii562jei88vpm51h21bq0f0u6989qnm5px5951f25" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}