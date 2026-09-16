rule _20160921_2a4687842acdb7843675f91c11ae7986_20160921_3d83b7982fc5_4789 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4687842acdb7843675f91c11ae7986.js, 20160921_3d83b7982fc59266194f048e87fb066d.js, 20160921_6bf1e6b71f68264911cd95f601a6cc98.js, 20160921_91734b00fd54cd3dd10c5f20c35d7864.js, 20160921_f69cc523f43841dbc6246209e09d2b8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b483b885082d284a148ab2a97b57881cd387b85b477025ad126d680e158bc62"
    hash2       = "f14778492463eaa86aec448221dcd9e88defb1f42404b2b80d42b0d0c41ffa66"
    hash3       = "3380b40f96f91c57b2ab0fcc0353b9938919cdb262f565dd84233769eb1a8842"
    hash4       = "cdae8af0c395dfe20c83f759c05d2fd6ae2859606871798c6b3a7a12257c7f70"
    hash5       = "82ee8104aecfd309a85de470b641e14f7ef67f3b3ec968ce41eade759620fd53"

  strings:
    $s1 = "),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){r" ascii
    $s2 = "\"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s3 = "{return \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})()" ascii
    $s4 = "on fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"" ascii
    $s5 = "unction fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}