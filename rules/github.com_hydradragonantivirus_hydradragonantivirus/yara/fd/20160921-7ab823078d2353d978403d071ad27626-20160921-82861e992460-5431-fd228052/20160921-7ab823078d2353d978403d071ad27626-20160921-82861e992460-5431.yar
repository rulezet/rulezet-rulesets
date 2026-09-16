rule _20160921_7ab823078d2353d978403d071ad27626_20160921_82861e992460_5431 {
  meta:
    description = "datamaliciousorder - from files 20160921_7ab823078d2353d978403d071ad27626.js, 20160921_82861e992460412d02ca3f987da7d467.js, 20160921_c42fb5c75aea2648513013ad2eed9aaf.js, 20160921_dc1ff053e9dd688459c33dc98e88d636.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32692e808eb087cfb43babd004792978a1918b8bad58bd7576ad1e83a17c97f8"
    hash2       = "2ed6678fea06b2b66ef873575f3af904bb62f54913a37c77387208fd53da33ba"
    hash3       = "5c8cdf3dbb94e197c36e5744084d12e198ecdab7243d67654934aa1cc9bf7ae9"
    hash4       = "18a890096a5714e518b28d3f50f6487cfbc4164418daae1842b7d724e2c26bd6"

  strings:
    $s1 = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"P" ascii
    $s2 = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Qh\"" ascii
    $s3 = ",(function fuck(){return \"MUs\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck()" ascii
    $s4 = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Ik\";})(),(func" ascii
    $s5 = "){return \"Vb\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ZWu\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}