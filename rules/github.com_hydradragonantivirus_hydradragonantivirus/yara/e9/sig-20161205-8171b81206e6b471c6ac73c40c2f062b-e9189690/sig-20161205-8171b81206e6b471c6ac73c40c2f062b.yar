rule sig_20161205_8171b81206e6b471c6ac73c40c2f062b {
  meta:
    description = "datamaliciousorder - file 20161205_8171b81206e6b471c6ac73c40c2f062b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3b7268f80663453753f8a41823baf831616c57f72e1d0ced4ca7ffc91e7e821"

  strings:
    $s1 = "function _Sr2(s) {var _Ha9 = new Date();_Ha9.setUTCFullYear(\"2003\");if (_Ha9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Sr2(s) {var _Ha9 = new Date();_Ha9.setUTCFullYear(\"2003\");if (_Ha9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _TTh6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}