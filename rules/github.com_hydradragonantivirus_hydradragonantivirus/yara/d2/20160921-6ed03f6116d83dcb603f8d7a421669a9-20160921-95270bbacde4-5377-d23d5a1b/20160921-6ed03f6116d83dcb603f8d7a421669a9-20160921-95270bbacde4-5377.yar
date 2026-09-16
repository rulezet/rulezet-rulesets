rule _20160921_6ed03f6116d83dcb603f8d7a421669a9_20160921_95270bbacde4_5377 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ed03f6116d83dcb603f8d7a421669a9.js, 20160921_95270bbacde4afcb3c799d7a0643809d.js, 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f10930e3c0bd956023b78dabf743464a690cb292b06d107d010614acff421c1"
    hash2       = "6cab57b5e35c3714b482592a77f0edbdc9fedb8c6e508d57b8cf63dfd719f5db"
    hash3       = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"

  strings:
    $s1 = "){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s2 = "rn \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"QDg\";})(),(f" ascii
    $s3 = "f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl" ascii
    $s4 = "GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(functio" ascii
    $s5 = "{return \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}