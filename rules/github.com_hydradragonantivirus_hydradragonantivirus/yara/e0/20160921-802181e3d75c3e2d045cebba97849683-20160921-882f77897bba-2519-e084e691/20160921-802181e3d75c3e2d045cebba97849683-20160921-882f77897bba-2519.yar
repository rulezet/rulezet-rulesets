rule _20160921_802181e3d75c3e2d045cebba97849683_20160921_882f77897bba_2519 {
  meta:
    description = "datamaliciousorder - from files 20160921_802181e3d75c3e2d045cebba97849683.js, 20160921_882f77897bba85afdc56810c29ef4cbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"
    hash2       = "9e1a86c6dc71a5b10659658c07a01bb1541887750ecf88ab56997c7dbc2d180c"

  strings:
    $s1 = "ion f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"SEo\";})(),(function f000(){return" ascii
    $s2 = ",(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){r" ascii
    $s3 = "{return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Iq\";})(" ascii
    $s4 = "unction f000(){return \"Lp\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s5 = "f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PT" ascii
    $s6 = "urn \"PTi\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})()," ascii
    $s7 = "urn \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(f" ascii
    $s8 = "00(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}