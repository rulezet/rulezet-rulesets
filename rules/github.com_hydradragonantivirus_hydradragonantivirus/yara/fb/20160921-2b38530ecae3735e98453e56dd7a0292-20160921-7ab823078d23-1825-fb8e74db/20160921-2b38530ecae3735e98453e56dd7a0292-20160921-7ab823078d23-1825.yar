rule _20160921_2b38530ecae3735e98453e56dd7a0292_20160921_7ab823078d23_1825 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b38530ecae3735e98453e56dd7a0292.js, 20160921_7ab823078d2353d978403d071ad27626.js, 20160921_82861e992460412d02ca3f987da7d467.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46f1595f803e301ed13d99315b244aac664f908c0c0d8ab508c1d104bf7ae947"
    hash2       = "32692e808eb087cfb43babd004792978a1918b8bad58bd7576ad1e83a17c97f8"
    hash3       = "2ed6678fea06b2b66ef873575f3af904bb62f54913a37c77387208fd53da33ba"

  strings:
    $s1  = "unction fuck(){return \"Yk\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retu" ascii
    $s2  = "\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Wo0\";})(),(function" ascii
    $s3  = " \"LGo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"MUs\";})(),(fu" ascii
    $s4  = "UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Jh\";})(),(functi" ascii
    $s5  = "n fuck(){return \"XCr\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"D" ascii
    $s6  = "),(function fuck(){return \"XHj\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"USf\";})(),(function fuck(" ascii
    $s7  = "rn \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"ADy\";})(),(f" ascii
    $s8  = "ck(){return \"Ot\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"OPz\"" ascii
    $s9  = " \"Vf\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(fun" ascii
    $s10 = "(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}