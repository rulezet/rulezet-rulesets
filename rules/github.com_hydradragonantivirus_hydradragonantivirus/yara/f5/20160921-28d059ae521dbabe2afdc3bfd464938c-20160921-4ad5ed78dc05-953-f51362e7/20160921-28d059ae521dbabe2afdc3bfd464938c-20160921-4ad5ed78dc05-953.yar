rule _20160921_28d059ae521dbabe2afdc3bfd464938c_20160921_4ad5ed78dc05_953 {
  meta:
    description = "datamaliciousorder - from files 20160921_28d059ae521dbabe2afdc3bfd464938c.js, 20160921_4ad5ed78dc05b02005f65ab785b9c74a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"
    hash2       = "7e5f9d362688f19111d3dbdf393d51e133fcc63eb7db27536cb31d1205ccc9e3"

  strings:
    $s1  = "nction f000(){return \"RLk\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yi\";})(),(function f000(){retur" ascii
    $s2  = "n \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s3  = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"EZu\";})" ascii
    $s4  = "0(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Nx\";" ascii
    $s5  = "eturn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"ZFe\";})(" ascii
    $s6  = "turn \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Mt\";})(),(" ascii
    $s7  = "(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TKl\";" ascii
    $s8  = "f000(){return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Br" ascii
    $s9  = "00(){return \"Go\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\"" ascii
    $s10 = "n \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s11 = "n f000(){return \"MMz\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s12 = "\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Br\";})(),(function f0" ascii
    $s13 = "(function f000(){return \"HJm\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s14 = "n f000(){return \"MMz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s15 = "turn \"Br\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(" ascii
    $s16 = ";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s17 = " f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"K" ascii
    $s18 = "return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})()," ascii
    $s19 = "GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s20 = "ction f000(){return \"Tn\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Br\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}