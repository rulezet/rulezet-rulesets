rule _20160921_71668d4dffd1de11d5c597a2f98e2266_20160921_7a3c07ee9b5a_1894 {
  meta:
    description = "datamaliciousorder - from files 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_dc989bc33de845eef9826b241e933829.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash2       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"
    hash3       = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash4       = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"

  strings:
    $s1  = "unction f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){retu" ascii
    $s2  = "function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"ZIi\";})(),(function f000(){re" ascii
    $s3  = "ction f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){retu" ascii
    $s4  = "){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";}" ascii
    $s5  = "function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){re" ascii
    $s6  = "(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(" ascii
    $s7  = "GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function" ascii
    $s8  = " \"SEo\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s9  = "{return \"Iq\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Vu\";})()," ascii
    $s10 = "00(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Uo" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}