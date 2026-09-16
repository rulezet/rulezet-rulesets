rule _20160921_3b3df29e27c35ab2e50a3446fa67bf66_20160921_87f13d652177_2897 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_87f13d652177c2ccba1196dd341efb6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash2       = "52cce778f06a6477b6f4a6a9f48328a81d874164235533c2925fdd358b6279c3"

  strings:
    $s1 = "000(){return \"RLk\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb" ascii
    $s2 = "n \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s3 = "unction f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTs\";})(),(function f000(){re" ascii
    $s4 = "00(){return \"Lp\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s5 = "function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){r" ascii
    $s6 = "(function f000(){return \"KDh\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})(),(function f000(){" ascii
    $s7 = "),(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"YTp\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}