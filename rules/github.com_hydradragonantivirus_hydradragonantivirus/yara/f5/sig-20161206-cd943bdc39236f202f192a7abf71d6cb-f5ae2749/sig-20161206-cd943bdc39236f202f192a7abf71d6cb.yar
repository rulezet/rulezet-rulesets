rule sig_20161206_cd943bdc39236f202f192a7abf71d6cb {
  meta:
    description = "datamaliciousorder - file 20161206_cd943bdc39236f202f192a7abf71d6cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b1f073c0aa661ec29daf35773455d1f04575c070238c90cce5edd3f3168b48d"

  strings:
    $s1 = "function _Ml3(s) {var _Fz1 = new Date();_Fz1.setUTCFullYear(\"2003\");if (_Fz1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ml3(s) {var _Fz1 = new Date();_Fz1.setUTCFullYear(\"2003\");if (_Fz1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _UKx6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}