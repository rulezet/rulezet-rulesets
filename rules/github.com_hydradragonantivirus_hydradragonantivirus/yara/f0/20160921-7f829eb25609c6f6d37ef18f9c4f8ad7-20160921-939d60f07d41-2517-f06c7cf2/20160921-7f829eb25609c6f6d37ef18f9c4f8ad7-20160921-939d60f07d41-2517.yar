rule _20160921_7f829eb25609c6f6d37ef18f9c4f8ad7_20160921_939d60f07d41_2517 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js, 20160921_939d60f07d4171a5bae4c0b4ca33f3d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"
    hash2       = "c23bfef986de7a073bbcd781aa45ad15287fb2c448d110b92a01e652f22ff335"

  strings:
    $s1 = "on f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"" ascii
    $s2 = "})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f0" ascii
    $s3 = "})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Um\";})(),(function f00" ascii
    $s4 = "00(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\"" ascii
    $s5 = "\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f0" ascii
    $s6 = "j\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s7 = "(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Qz\";})(),(function f000()" ascii
    $s8 = "n \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vj\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}