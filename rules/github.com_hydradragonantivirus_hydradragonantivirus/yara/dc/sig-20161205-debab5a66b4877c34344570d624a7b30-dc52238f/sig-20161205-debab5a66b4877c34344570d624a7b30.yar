rule sig_20161205_debab5a66b4877c34344570d624a7b30 {
  meta:
    description = "datamaliciousorder - file 20161205_debab5a66b4877c34344570d624a7b30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1482e5a3a21dbcca345dd95fa8eb20bfacf4215376efcb013ab99bf4428bcbd"

  strings:
    $s1 = "function _FDy2(s) {var _JMy8 = new Date();_JMy8.setUTCFullYear(\"2003\");if (_JMy8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _FDy2(s) {var _JMy8 = new Date();_JMy8.setUTCFullYear(\"2003\");if (_JMy8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _CSd0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}