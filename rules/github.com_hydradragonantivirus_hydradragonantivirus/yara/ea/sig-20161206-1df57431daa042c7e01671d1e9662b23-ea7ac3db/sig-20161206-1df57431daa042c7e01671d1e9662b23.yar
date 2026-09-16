rule sig_20161206_1df57431daa042c7e01671d1e9662b23 {
  meta:
    description = "datamaliciousorder - file 20161206_1df57431daa042c7e01671d1e9662b23.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03fb42263f357ce0d7bb86e3bd9017a20ffdd48e8f44e155d6278bcde8442c2d"

  strings:
    $s1 = "function _Jj3(s) {var _Oo1 = new Date();_Oo1.setUTCFullYear(\"2003\");if (_Oo1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Jj3(s) {var _Oo1 = new Date();_Oo1.setUTCFullYear(\"2003\");if (_Oo1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _TLi8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}