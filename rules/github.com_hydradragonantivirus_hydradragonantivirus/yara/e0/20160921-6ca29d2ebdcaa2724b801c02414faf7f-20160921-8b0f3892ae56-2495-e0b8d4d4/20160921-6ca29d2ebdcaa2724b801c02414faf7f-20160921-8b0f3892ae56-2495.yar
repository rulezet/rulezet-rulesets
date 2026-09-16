rule _20160921_6ca29d2ebdcaa2724b801c02414faf7f_20160921_8b0f3892ae56_2495 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ca29d2ebdcaa2724b801c02414faf7f.js, 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b810435d98ebab77ad9d2cd316e2a0c0211b0941d86cbfa6c0e753732c6d3b15"
    hash2       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"

  strings:
    $s1 = " \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s2 = "\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yz\";})(),(function f0" ascii
    $s3 = "00(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn" ascii
    $s4 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"PTs\";})(" ascii
    $s5 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f00" ascii
    $s6 = ",(function f000(){return \"Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){r" ascii
    $s7 = "turn \"ZFe\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})()" ascii
    $s8 = "on f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}