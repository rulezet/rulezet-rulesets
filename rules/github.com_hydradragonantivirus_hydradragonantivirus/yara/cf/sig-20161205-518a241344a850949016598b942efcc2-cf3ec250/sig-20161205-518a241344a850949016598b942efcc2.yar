rule sig_20161205_518a241344a850949016598b942efcc2 {
  meta:
    description = "datamaliciousorder - file 20161205_518a241344a850949016598b942efcc2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7344e4378aad571a4ae6258e03f200f499b3d3913803bc5458551ec882091a6a"

  strings:
    $s1 = "function _UQw7(s) {var _Yy8 = new Date();_Yy8.setUTCFullYear(\"2003\");if (_Yy8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _UQw7(s) {var _Yy8 = new Date();_Yy8.setUTCFullYear(\"2003\");if (_Yy8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _WAr8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}