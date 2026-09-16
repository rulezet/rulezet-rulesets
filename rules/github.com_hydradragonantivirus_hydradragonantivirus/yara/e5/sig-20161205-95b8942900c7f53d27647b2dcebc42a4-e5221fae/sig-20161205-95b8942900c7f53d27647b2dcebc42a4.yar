rule sig_20161205_95b8942900c7f53d27647b2dcebc42a4 {
  meta:
    description = "datamaliciousorder - file 20161205_95b8942900c7f53d27647b2dcebc42a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de67634893032aaeb417bf3376e44452b2233dc658e059a2276e030c3fa653ce"

  strings:
    $s1 = "function _BOe1(s) {var _Oy6 = new Date();_Oy6.setUTCFullYear(\"2003\");if (_Oy6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _BOe1(s) {var _Oy6 = new Date();_Oy6.setUTCFullYear(\"2003\");if (_Oy6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _JYf1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}