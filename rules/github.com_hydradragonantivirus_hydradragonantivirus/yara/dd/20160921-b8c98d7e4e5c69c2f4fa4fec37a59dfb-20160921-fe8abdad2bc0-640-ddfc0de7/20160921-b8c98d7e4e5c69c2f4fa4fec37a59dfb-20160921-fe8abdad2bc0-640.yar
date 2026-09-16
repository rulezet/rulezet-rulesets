rule _20160921_b8c98d7e4e5c69c2f4fa4fec37a59dfb_20160921_fe8abdad2bc0_640 {
  meta:
    description = "datamaliciousorder - from files 20160921_b8c98d7e4e5c69c2f4fa4fec37a59dfb.js, 20160921_fe8abdad2bc00d1378e2964402e33217.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1ea05bc317ec861954db64b30bd293d8ee2f663106d48389d91cfb77247fb1e"
    hash2       = "39d0496129988da40dbbddcff6610a39be1f05ddd7f48a13058b749810c8400d"

  strings:
    $s1  = "0(){return \"ZIi\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Ml\";" ascii
    $s2  = "){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";}" ascii
    $s3  = " f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do" ascii
    $s4  = "n f000(){return \"HJm\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return " ascii
    $s5  = "return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Fs\";})(" ascii
    $s6  = "00(){return \"WIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn" ascii
    $s7  = "turn \"NBs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s8  = "turn \"ZGq\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(" ascii
    $s9  = "eturn \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Wb\";})(),(" ascii
    $s10 = "000(){return \"Um\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s11 = "ion f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s12 = "n f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"" ascii
    $s13 = "turn \"ZGq\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"NBs\";})(),(" ascii
    $s14 = "function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DYs\";})(),(function f000(){re" ascii
    $s15 = "rn \"NBs\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fu" ascii
    $s16 = "\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f" ascii
    $s17 = "rn \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(fun" ascii
    $s18 = "0(){return \"MMz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\"" ascii
    $s19 = "{return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"NBs\";})" ascii
    $s20 = "nction f000(){return \"IPu\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}