rule sig_20161205_b3f3a4e90c88da20bea748c8ae21e828 {
  meta:
    description = "datamaliciousorder - file 20161205_b3f3a4e90c88da20bea748c8ae21e828.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41b63d25cf437d6e3f268f17acdb105e8cdb58ae086959ca171a90230faf7f55"

  strings:
    $s1 = "function _EYe0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii
    $s2 = "function _Ez8(s) {var _Pr3 = new Date();_Pr3.setUTCFullYear(\"2003\");if (_Pr3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Ez8(s) {var _Pr3 = new Date();_Pr3.setUTCFullYear(\"2003\");if (_Pr3.getUTCFullYear().toString(10) == \"2003\") return" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}