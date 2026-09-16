rule _20160921_203e0165d7eb1b32389bd0efd4bc9546_20160921_5f7be0b4d162_3501 {
  meta:
    description = "datamaliciousorder - from files 20160921_203e0165d7eb1b32389bd0efd4bc9546.js, 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9112c30f4cc79af123a3f3e13b1e01a29f2419955988701cb25a673fdfe684d"
    hash2       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"

  strings:
    $s1 = ")(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Cd\";})(),(function fuck" ascii
    $s2 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Za\";})(),(function fuck()" ascii
    $s3 = "),(function fuck(){return \"Ai\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s4 = "urn \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(" ascii
    $s5 = "k(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Vb\";" ascii
    $s6 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}