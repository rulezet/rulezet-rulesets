rule sig_20161205_62238fb9884e06968a308fbdac3fe97f {
  meta:
    description = "datamaliciousorder - file 20161205_62238fb9884e06968a308fbdac3fe97f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce705755137a81a962911bb6acee7e43a968f4e16db42036397e4e575a3b7057"

  strings:
    $s1 = "function _Nn2(s) {var _Jp2 = new Date();_Jp2.setUTCFullYear(\"2003\");if (_Jp2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Nn2(s) {var _Jp2 = new Date();_Jp2.setUTCFullYear(\"2003\");if (_Jp2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Vn5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}