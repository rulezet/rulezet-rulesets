rule sig_20161205_bb3b2cb6e90b818c5143e155ce1c5602 {
  meta:
    description = "datamaliciousorder - file 20161205_bb3b2cb6e90b818c5143e155ce1c5602.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37c2bbd401df886d76a26b4706830e78690c839310f6b97b7ec4e91b005e8e05"

  strings:
    $s1 = "function _Ur9(s) {var _Fl9 = new Date();_Fl9.setUTCFullYear(\"2003\");if (_Fl9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ur9(s) {var _Fl9 = new Date();_Fl9.setUTCFullYear(\"2003\");if (_Fl9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _CRe8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}