rule _20160921_2f8fa7cee8a6f4f78978b7417f3f700e_20160921_7ab823078d23_3588 {
  meta:
    description = "datamaliciousorder - from files 20160921_2f8fa7cee8a6f4f78978b7417f3f700e.js, 20160921_7ab823078d2353d978403d071ad27626.js, 20160921_82861e992460412d02ca3f987da7d467.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6410122a95cd840a4eef622389d8026475b4f6a156d4b5288cf227165c036c96"
    hash2       = "32692e808eb087cfb43babd004792978a1918b8bad58bd7576ad1e83a17c97f8"
    hash3       = "2ed6678fea06b2b66ef873575f3af904bb62f54913a37c77387208fd53da33ba"

  strings:
    $s1 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return " ascii
    $s2 = "return \"Et\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s3 = "ction fuck(){return \"IOs\";})(),(function fuck(){return \"Az\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){retur" ascii
    $s4 = "Ot\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s5 = "nction fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retu" ascii
    $s6 = "f\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"RAi\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}