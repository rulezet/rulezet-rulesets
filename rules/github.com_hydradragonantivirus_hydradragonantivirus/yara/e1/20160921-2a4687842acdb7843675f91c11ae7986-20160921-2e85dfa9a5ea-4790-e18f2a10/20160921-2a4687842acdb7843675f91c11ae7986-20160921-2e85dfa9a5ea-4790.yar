rule _20160921_2a4687842acdb7843675f91c11ae7986_20160921_2e85dfa9a5ea_4790 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4687842acdb7843675f91c11ae7986.js, 20160921_2e85dfa9a5ea92be677fa9eceee4f8b1.js, 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_ecd98b74e6a52b1227b09228f92cb495.js, 20160921_f69cc523f43841dbc6246209e09d2b8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b483b885082d284a148ab2a97b57881cd387b85b477025ad126d680e158bc62"
    hash2       = "fd958e388f97aa8b73e103ada622a36250446b5740c2e70d0bf844240c0968c2"
    hash3       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash4       = "8930637b40db8c97df91bff2cf5b4021d0bcb2f6a204f27249176fe3d6d4120e"
    hash5       = "82ee8104aecfd309a85de470b641e14f7ef67f3b3ec968ce41eade759620fd53"

  strings:
    $s1 = "ion fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return" ascii
    $s2 = "eturn \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LLv\";})(" ascii
    $s3 = ";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function f" ascii
    $s4 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return " ascii
    $s5 = "{return \"OQr\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GNm\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}