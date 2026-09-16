rule _20160921_a1cbb43a1e22a4b1fd63ee1a724173eb_20160921_da7f7f057c35_169 {
  meta:
    description = "datamaliciousorder - from files 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_da7f7f057c35b886425ec822f654da90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash2       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"

  strings:
    $s1  = "rn \"Vj\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s2  = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return " ascii
    $s3  = "n\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function " ascii
    $s4  = "turn \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"NBs\";})()," ascii
    $s5  = "{return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Br\";})(" ascii
    $s6  = "urn \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(" ascii
    $s7  = "\"PTi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s8  = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){retu" ascii
    $s9  = "(),(function f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"ZGq\";})(),(function f000" ascii
    $s10 = "n f000(){return \"Wy\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Do" ascii
    $s11 = "f000(){return \"PTs\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"MD" ascii
    $s12 = "function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZFe\";})(),(function f000(){r" ascii
    $s13 = "00(){return \"Ml\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";" ascii
    $s14 = "00(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"MMz" ascii
    $s15 = "unction f000(){return \"Oe\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){retu" ascii
    $s16 = ")(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DIa\";})(),(function f000(" ascii
    $s17 = "){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Lp\";})(" ascii
    $s18 = "(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){r" ascii
    $s19 = "f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZG" ascii
    $s20 = "0(){return \"Wy\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Br\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}