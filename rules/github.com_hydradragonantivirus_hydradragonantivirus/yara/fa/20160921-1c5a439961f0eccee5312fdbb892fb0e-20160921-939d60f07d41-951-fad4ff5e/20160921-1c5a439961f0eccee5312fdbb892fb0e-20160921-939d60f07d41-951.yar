rule _20160921_1c5a439961f0eccee5312fdbb892fb0e_20160921_939d60f07d41_951 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160921_939d60f07d4171a5bae4c0b4ca33f3d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash2       = "c23bfef986de7a073bbcd781aa45ad15287fb2c448d110b92a01e652f22ff335"

  strings:
    $s1  = " f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Y" ascii
    $s2  = "Xg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s3  = ",(function f000(){return \"RLk\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Vj\";})(),(function f000(){r" ascii
    $s4  = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sq" ascii
    $s5  = " \"MMz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wh\";})(),(fun" ascii
    $s6  = " f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Z" ascii
    $s7  = "function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){re" ascii
    $s8  = "00(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn" ascii
    $s9  = "RLk\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s10 = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){ret" ascii
    $s11 = "})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s12 = "urn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZGq\";})(),(" ascii
    $s13 = "(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000()" ascii
    $s14 = "(),(function f000(){return \"ZGq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(" ascii
    $s15 = "{return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";}" ascii
    $s16 = "n \"OUx\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s17 = "eturn \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RPt\";})()" ascii
    $s18 = "00(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb" ascii
    $s19 = "\"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s20 = "){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}