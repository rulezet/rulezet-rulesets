rule sig_20161205_555d09f73fa57272ef842960f6d1f3fb {
  meta:
    description = "datamaliciousorder - file 20161205_555d09f73fa57272ef842960f6d1f3fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e61ea940881657eb4af4ea7e37fbd5816dd31f2822b2715fbb32f28817d5cfd9"

  strings:
    $s1 = "function _YIx9(s) {var _WPd5 = new Date();_WPd5.setUTCFullYear(\"2003\");if (_WPd5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _YIx9(s) {var _WPd5 = new Date();_WPd5.setUTCFullYear(\"2003\");if (_WPd5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Yw5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}