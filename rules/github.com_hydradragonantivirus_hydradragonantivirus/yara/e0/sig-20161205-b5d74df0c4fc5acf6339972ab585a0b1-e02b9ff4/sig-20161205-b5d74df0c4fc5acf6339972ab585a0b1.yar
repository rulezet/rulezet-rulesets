rule sig_20161205_b5d74df0c4fc5acf6339972ab585a0b1 {
  meta:
    description = "datamaliciousorder - file 20161205_b5d74df0c4fc5acf6339972ab585a0b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e59d37527ff3a4be7114f64cdb3640e00083666b894a6be61c83a90b2e576abc"

  strings:
    $s1 = "function _DAo6(s) {var _Pc6 = new Date();_Pc6.setUTCFullYear(\"2003\");if (_Pc6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _DAo6(s) {var _Pc6 = new Date();_Pc6.setUTCFullYear(\"2003\");if (_Pc6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Fv3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}