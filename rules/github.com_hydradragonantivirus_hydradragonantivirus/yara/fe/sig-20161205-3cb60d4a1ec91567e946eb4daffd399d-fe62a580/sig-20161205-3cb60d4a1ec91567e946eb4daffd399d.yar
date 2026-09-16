rule sig_20161205_3cb60d4a1ec91567e946eb4daffd399d {
  meta:
    description = "datamaliciousorder - file 20161205_3cb60d4a1ec91567e946eb4daffd399d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f12c98bcc18aac1e2145b04028292eb82d7f23dc87740ffa60683115885bb512"

  strings:
    $s1 = "function _QYv5(s) {var _Bf6 = new Date();_Bf6.setUTCFullYear(\"2003\");if (_Bf6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _QYv5(s) {var _Bf6 = new Date();_Bf6.setUTCFullYear(\"2003\");if (_Bf6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Vk1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}