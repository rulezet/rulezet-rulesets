rule _20160921_41f7b3abc606ff1ddad7593361eaa449_20160921_4bad0ae96eb9_5036 {
  meta:
    description = "datamaliciousorder - from files 20160921_41f7b3abc606ff1ddad7593361eaa449.js, 20160921_4bad0ae96eb9fc3a1c603846a44ffe13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53e06a7234c6522ba26a61e46d13312e1063594b0e33bec9fae49d2dc4b77c28"
    hash2       = "a99f235f58613323f5c58def3503d47959f4a77f0697e30c75b6d221c4b40806"

  strings:
    $s1 = "})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Sx\";})(),(function fuck(" ascii
    $s2 = "return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\";})()" ascii
    $s3 = "(function fuck(){return \"Yk\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){ret" ascii
    $s4 = "rn \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Xw\";})(),(fu" ascii
    $s5 = "g\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Ik\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}