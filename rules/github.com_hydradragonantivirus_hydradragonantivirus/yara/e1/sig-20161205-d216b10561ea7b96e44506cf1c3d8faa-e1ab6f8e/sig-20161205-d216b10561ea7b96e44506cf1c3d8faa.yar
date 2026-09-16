rule sig_20161205_d216b10561ea7b96e44506cf1c3d8faa {
  meta:
    description = "datamaliciousorder - file 20161205_d216b10561ea7b96e44506cf1c3d8faa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff818fa362f17546e4617d1e535afe9bc8df5e3c22ba63342c04c984c3554f05"

  strings:
    $s1 = "function _Or8(s) {var _Oe7 = new Date();_Oe7.setUTCFullYear(\"2003\");if (_Oe7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Or8(s) {var _Oe7 = new Date();_Oe7.setUTCFullYear(\"2003\");if (_Oe7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _PWb7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}