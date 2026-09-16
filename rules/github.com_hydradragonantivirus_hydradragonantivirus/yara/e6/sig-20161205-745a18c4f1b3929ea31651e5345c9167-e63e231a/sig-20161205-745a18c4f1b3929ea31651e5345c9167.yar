rule sig_20161205_745a18c4f1b3929ea31651e5345c9167 {
  meta:
    description = "datamaliciousorder - file 20161205_745a18c4f1b3929ea31651e5345c9167.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04b3465c6e503b71a8c3fdc0fd85ae979b7bd5433ddb4afb945ff61b38fdfd68"

  strings:
    $s1 = "function _TIm8(s) {var _XVz1 = new Date();_XVz1.setUTCFullYear(\"2003\");if (_XVz1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _TIm8(s) {var _XVz1 = new Date();_XVz1.setUTCFullYear(\"2003\");if (_XVz1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Th1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}