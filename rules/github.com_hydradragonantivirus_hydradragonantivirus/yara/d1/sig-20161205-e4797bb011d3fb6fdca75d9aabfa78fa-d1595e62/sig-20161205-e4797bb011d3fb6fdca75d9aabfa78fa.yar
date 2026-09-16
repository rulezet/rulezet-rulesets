rule sig_20161205_e4797bb011d3fb6fdca75d9aabfa78fa {
  meta:
    description = "datamaliciousorder - file 20161205_e4797bb011d3fb6fdca75d9aabfa78fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39d1d6810b7e19b6b5edb4684026a6d2819dcf8f41bcd25f9c27cfb672507a10"

  strings:
    $s1 = "function _Dv1(s) {var _Af9 = new Date();_Af9.setUTCFullYear(\"2003\");if (_Af9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Dv1(s) {var _Af9 = new Date();_Af9.setUTCFullYear(\"2003\");if (_Af9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Wq4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}