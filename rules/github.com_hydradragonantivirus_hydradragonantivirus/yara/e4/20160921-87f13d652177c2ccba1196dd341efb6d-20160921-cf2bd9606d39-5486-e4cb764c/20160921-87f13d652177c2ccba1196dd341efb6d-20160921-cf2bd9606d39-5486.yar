rule _20160921_87f13d652177c2ccba1196dd341efb6d_20160921_cf2bd9606d39_5486 {
  meta:
    description = "datamaliciousorder - from files 20160921_87f13d652177c2ccba1196dd341efb6d.js, 20160921_cf2bd9606d396ba99f8174f1946c8590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52cce778f06a6477b6f4a6a9f48328a81d874164235533c2925fdd358b6279c3"
    hash2       = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"

  strings:
    $s1 = ")(),(function f000(){return \"KDh\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})(),(function f00" ascii
    $s2 = ")(),(function f000(){return \"Wb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(" ascii
    $s3 = "(),(function f000(){return \"WIj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Nv\";})(),(function f000()" ascii
    $s4 = "return \"ZIi\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})" ascii
    $s5 = " f000(){return \"PTs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MD" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}