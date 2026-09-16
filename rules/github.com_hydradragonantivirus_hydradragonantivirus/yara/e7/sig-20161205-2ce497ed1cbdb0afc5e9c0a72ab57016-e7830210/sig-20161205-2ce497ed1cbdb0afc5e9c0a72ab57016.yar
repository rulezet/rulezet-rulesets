rule sig_20161205_2ce497ed1cbdb0afc5e9c0a72ab57016 {
  meta:
    description = "datamaliciousorder - file 20161205_2ce497ed1cbdb0afc5e9c0a72ab57016.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23df663f0a0ea6c8eed5b8f5c086e788ee6e536921960160f2cb34d7d217b849"

  strings:
    $s1 = "function _XAr3(s) {var _TRh9 = new Date();_TRh9.setUTCFullYear(\"2003\");if (_TRh9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _XAr3(s) {var _TRh9 = new Date();_TRh9.setUTCFullYear(\"2003\");if (_TRh9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _ILh2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}