rule sig_20161205_c6e0dccb477262d4f3836cf073de7cd5 {
  meta:
    description = "datamaliciousorder - file 20161205_c6e0dccb477262d4f3836cf073de7cd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "731f3505ae05aa3009f4d0e25bfe984d44c80b409fdda3f1b645403bd894de88"

  strings:
    $s1 = "function _Ls2(s) {var _NKb9 = new Date();_NKb9.setUTCFullYear(\"2003\");if (_NKb9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ls2(s) {var _NKb9 = new Date();_NKb9.setUTCFullYear(\"2003\");if (_NKb9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _EKq1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}