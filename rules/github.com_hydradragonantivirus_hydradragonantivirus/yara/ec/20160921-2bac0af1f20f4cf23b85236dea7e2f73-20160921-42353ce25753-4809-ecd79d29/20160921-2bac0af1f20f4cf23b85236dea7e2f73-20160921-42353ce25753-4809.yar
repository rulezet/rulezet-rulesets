rule _20160921_2bac0af1f20f4cf23b85236dea7e2f73_20160921_42353ce25753_4809 {
  meta:
    description = "datamaliciousorder - from files 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js, 20160921_42353ce257534ed06a8c73cebdde12dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"
    hash2       = "68261e17878fc3b618b0fec34ae97fb6fea1090c52fff206192cb972d23b2b35"

  strings:
    $s1 = "nction fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retur" ascii
    $s2 = " fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"" ascii
    $s3 = "{return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})" ascii
    $s4 = "(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";" ascii
    $s5 = "n fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}