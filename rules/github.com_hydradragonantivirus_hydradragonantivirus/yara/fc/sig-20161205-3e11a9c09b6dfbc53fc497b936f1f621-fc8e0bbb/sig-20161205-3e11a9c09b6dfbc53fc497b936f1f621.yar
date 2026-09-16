rule sig_20161205_3e11a9c09b6dfbc53fc497b936f1f621 {
  meta:
    description = "datamaliciousorder - file 20161205_3e11a9c09b6dfbc53fc497b936f1f621.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "123cc9e89d1819f42a0688d0ed178205ce518572d0c2c3c9b53323a6150df865"

  strings:
    $s1 = "function _Al6(s) {var _Hx2 = new Date();_Hx2.setUTCFullYear(\"2003\");if (_Hx2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Al6(s) {var _Hx2 = new Date();_Hx2.setUTCFullYear(\"2003\");if (_Hx2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _ABa8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}