rule sig_20161205_33beecaf0da6ffbb52b9edff6b4f4c29 {
  meta:
    description = "datamaliciousorder - file 20161205_33beecaf0da6ffbb52b9edff6b4f4c29.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e21ccafd867896ce7c05fbad49dad2a7c489d119301ebb8c073cb2f6e1d73d47"

  strings:
    $s1 = "function _Dh7(s) {var _Dj9 = new Date();_Dj9.setUTCFullYear(\"2003\");if (_Dj9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Dh7(s) {var _Dj9 = new Date();_Dj9.setUTCFullYear(\"2003\");if (_Dj9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _WRb7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}