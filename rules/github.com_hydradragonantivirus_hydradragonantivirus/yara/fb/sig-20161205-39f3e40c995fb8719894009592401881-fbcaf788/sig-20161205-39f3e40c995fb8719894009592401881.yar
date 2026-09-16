rule sig_20161205_39f3e40c995fb8719894009592401881 {
  meta:
    description = "datamaliciousorder - file 20161205_39f3e40c995fb8719894009592401881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fbf4430540784148501598f7508a41187818f597d5824176d8740ce5869d07e"

  strings:
    $s1 = "function _Qy8(s) {var _GHw7 = new Date();_GHw7.setUTCFullYear(\"2003\");if (_GHw7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Qy8(s) {var _GHw7 = new Date();_GHw7.setUTCFullYear(\"2003\");if (_GHw7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Bu6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}