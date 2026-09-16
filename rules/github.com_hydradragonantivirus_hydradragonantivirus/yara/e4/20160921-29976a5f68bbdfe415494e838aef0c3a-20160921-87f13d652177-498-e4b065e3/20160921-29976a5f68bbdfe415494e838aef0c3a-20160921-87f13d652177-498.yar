rule _20160921_29976a5f68bbdfe415494e838aef0c3a_20160921_87f13d652177_498 {
  meta:
    description = "datamaliciousorder - from files 20160921_29976a5f68bbdfe415494e838aef0c3a.js, 20160921_87f13d652177c2ccba1196dd341efb6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "218bc62c15296caf93128e0a5e06fde374e19fd4150b6c9b1def4d962554ef39"
    hash2       = "52cce778f06a6477b6f4a6a9f48328a81d874164235533c2925fdd358b6279c3"

  strings:
    $s1  = "(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Yi\";})" ascii
    $s2  = "unction f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"NYh\";})(),(function f000(){ret" ascii
    $s3  = "0(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"YTp" ascii
    $s4  = "m\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s5  = "s\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s6  = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s7  = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Km\"" ascii
    $s8  = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Yz\";})()" ascii
    $s9  = "urn \"XTn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Lp\";})(),(" ascii
    $s10 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"PTi\";})(" ascii
    $s11 = "\"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"OMd\";})(),(func" ascii
    $s12 = "nction f000(){return \"SGs\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii
    $s13 = "){return \"SEo\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";}" ascii
    $s14 = "Kw\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(functi" ascii
    $s15 = "tion f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s16 = "Yh\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s17 = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"L" ascii
    $s18 = "n \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s19 = "0(){return \"RPt\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\"" ascii
    $s20 = ")(),(function f000(){return \"ZFe\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}