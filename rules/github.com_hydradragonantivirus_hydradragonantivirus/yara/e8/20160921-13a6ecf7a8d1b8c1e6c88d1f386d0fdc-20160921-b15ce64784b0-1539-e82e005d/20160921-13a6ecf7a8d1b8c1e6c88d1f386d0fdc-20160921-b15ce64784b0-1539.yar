rule _20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc_20160921_b15ce64784b0_1539 {
  meta:
    description = "datamaliciousorder - from files 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_b15ce64784b080eff109e1bd1b00ebf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash2       = "e78e24f62fb93be4551c02ce2a2a27421a39d4a9d5c77d37c7518adf9e53ce65"

  strings:
    $s1  = "f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WI" ascii
    $s2  = "(function f000(){return \"Sv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Tn\";})(),(function f000(){re" ascii
    $s3  = "unction f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){ret" ascii
    $s4  = ",(function f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"SGs\";})(),(function f000()" ascii
    $s5  = "ction f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"PTi\";})(),(function f000(){retur" ascii
    $s6  = "o\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OUx\";})(),(function" ascii
    $s7  = "000(){return \"Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn" ascii
    $s8  = "n \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(fu" ascii
    $s9  = "{return \"Sv\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})" ascii
    $s10 = "(){return \"Lo\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s11 = "Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s12 = "unction f000(){return \"Qa\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}