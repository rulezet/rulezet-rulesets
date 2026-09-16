rule _20160921_072d194212f8a9a2728f7fb6d5953933_20160921_52f9b0fa9588_4289 {
  meta:
    description = "datamaliciousorder - from files 20160921_072d194212f8a9a2728f7fb6d5953933.js, 20160921_52f9b0fa9588abb39dc8ffa331cd277b.js, 20160921_5645898a54dfcbd78b32ee6da656f545.js, 20160921_70b567ca258b3c505e14f3c712366f09.js, 20160921_c38068bdcf6149dc68d38cbcccfe991f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c215f339e3128df4a73ba4ad5b1db80d6620de77bd285fef1d86107197eace"
    hash2       = "7a84827d35b2b189a2872cc9d16d3ab675e3ec50c203690e75cf66ab54056731"
    hash3       = "0d8d12c1edd9af4fca97f4e7013b538499acfb96d7d0bed0a7b5419e888829b1"
    hash4       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"
    hash5       = "d59dd40562ac50a453dbb7054114c62cfd7c63d24b81c776b35af40fb9aa3480"

  strings:
    $s1 = "n fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return " ascii
    $s2 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){retu" ascii
    $s3 = "eturn \"FJs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s4 = "rn \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"MOj\";})(),(f" ascii
    $s5 = "f\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}