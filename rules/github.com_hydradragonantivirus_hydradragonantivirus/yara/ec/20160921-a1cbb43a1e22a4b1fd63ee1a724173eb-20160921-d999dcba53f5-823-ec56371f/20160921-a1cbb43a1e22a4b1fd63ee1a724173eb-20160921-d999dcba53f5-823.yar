rule _20160921_a1cbb43a1e22a4b1fd63ee1a724173eb_20160921_d999dcba53f5_823 {
  meta:
    description = "datamaliciousorder - from files 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js, 20160921_da7f7f057c35b886425ec822f654da90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash2       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"
    hash3       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"

  strings:
    $s1  = "rn \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(fu" ascii
    $s2  = "000(){return \"Um\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn" ascii
    $s3  = "n f000(){return \"MMz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return " ascii
    $s4  = "0(){return \"YTp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s5  = "),(function f000(){return \"ZIi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"ZGq\";})(),(function f000()" ascii
    $s6  = "\"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(funct" ascii
    $s7  = "ZIi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Ml\";})(),(functio" ascii
    $s8  = "0(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Wb\";}" ascii
    $s9  = "(),(function f000(){return \"PTs\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"TKp\";})(),(function f000" ascii
    $s10 = "00(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\"" ascii
    $s11 = ",(function f000(){return \"Tb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s12 = "(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";}" ascii
    $s13 = "urn \"TKp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s14 = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Oh\";})(),(func" ascii
    $s15 = "nction f000(){return \"HJm\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){ret" ascii
    $s16 = " \"RLk\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s17 = "t\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function " ascii
    $s18 = "Gq\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(functio" ascii
    $s19 = "rn \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Lp\";})(),(f" ascii
    $s20 = "urn \"QDg\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"SGs\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}