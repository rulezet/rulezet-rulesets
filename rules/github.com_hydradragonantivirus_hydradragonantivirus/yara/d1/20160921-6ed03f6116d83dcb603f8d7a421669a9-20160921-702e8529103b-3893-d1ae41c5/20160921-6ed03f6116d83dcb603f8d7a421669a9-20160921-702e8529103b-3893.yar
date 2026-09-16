rule _20160921_6ed03f6116d83dcb603f8d7a421669a9_20160921_702e8529103b_3893 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ed03f6116d83dcb603f8d7a421669a9.js, 20160921_702e8529103b960a902ddb030da0de45.js, 20160921_95270bbacde4afcb3c799d7a0643809d.js, 20160921_b4c84c92954782bcf19013150a359ec6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f10930e3c0bd956023b78dabf743464a690cb292b06d107d010614acff421c1"
    hash2       = "cf8ba9fdbe4ef225cb892f7294538710b1dd7e8bc4e280897680c51e03816d1c"
    hash3       = "6cab57b5e35c3714b482592a77f0edbdc9fedb8c6e508d57b8cf63dfd719f5db"
    hash4       = "deac288c0b80bcd19eff4e9a4bb55e7bdc0f08b0110094a0693c671b47cda285"

  strings:
    $s1 = "tion f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s2 = "tion f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s3 = "return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})" ascii
    $s4 = " \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s5 = "turn \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s6 = " f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}