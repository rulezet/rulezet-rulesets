rule sig_20161205_31e5a7971379d19796ca6a0f64bf6448 {
  meta:
    description = "datamaliciousorder - file 20161205_31e5a7971379d19796ca6a0f64bf6448.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88e370b2c94746a7af55f3e0738b9b04e0c3467b2ca682f0fb786edd0c2ce66e"

  strings:
    $s1 = "function _Et3(s) {var _ZXh9 = new Date();_ZXh9.setUTCFullYear(\"2003\");if (_ZXh9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Et3(s) {var _ZXh9 = new Date();_ZXh9.setUTCFullYear(\"2003\");if (_ZXh9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Or0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}