rule _20160921_939d60f07d4171a5bae4c0b4ca33f3d9_20160921_eba3e9dc8ad6_2148 {
  meta:
    description = "datamaliciousorder - from files 20160921_939d60f07d4171a5bae4c0b4ca33f3d9.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c23bfef986de7a073bbcd781aa45ad15287fb2c448d110b92a01e652f22ff335"
    hash2       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"

  strings:
    $s1 = "Lp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s2 = "nction f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){ret" ascii
    $s3 = ",(function f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Vu\";})(),(function f000(){r" ascii
    $s4 = " \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s5 = "n\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f" ascii
    $s6 = "){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";}" ascii
    $s7 = "f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Nx" ascii
    $s8 = "function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){r" ascii
    $s9 = "(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Ut\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}