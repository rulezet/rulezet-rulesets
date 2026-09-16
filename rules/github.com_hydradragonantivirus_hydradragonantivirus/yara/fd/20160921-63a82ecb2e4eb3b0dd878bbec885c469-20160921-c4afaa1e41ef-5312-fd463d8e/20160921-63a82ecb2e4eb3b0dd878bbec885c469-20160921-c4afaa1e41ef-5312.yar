rule _20160921_63a82ecb2e4eb3b0dd878bbec885c469_20160921_c4afaa1e41ef_5312 {
  meta:
    description = "datamaliciousorder - from files 20160921_63a82ecb2e4eb3b0dd878bbec885c469.js, 20160921_c4afaa1e41efa7633248f1941bda4010.js, 20160921_ce3c0604d52e9dc9119cefedfee34385.js, 20160921_e67c85fc609bef1c06233d9dc655b074.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e9de62be8773f33e42da56c84c9c85d07f7c2616909543479f7803e6794a9ef"
    hash2       = "64cdab0c251929ea414823662957bad76268a8398b0c708715609f37e7070a69"
    hash3       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"
    hash4       = "372b553e13a1b2dacf2c8938d6c7953212ff8112978d88f8aa1425ffa2ef21de"

  strings:
    $s1 = "turn \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})()," ascii
    $s2 = "(){return \"Wo0\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\"" ascii
    $s3 = "ion fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s4 = "MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo0\";})(),(functi" ascii
    $s5 = "\"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Yk\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}