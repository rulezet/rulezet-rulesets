rule sig_20161205_5bc2a16b4bbb5e40752ac047d6a83525 {
  meta:
    description = "datamaliciousorder - file 20161205_5bc2a16b4bbb5e40752ac047d6a83525.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85083ff5fd7bc501389cc55417a29261da23e8872a1e8f8b7416877656cb8e9d"

  strings:
    $s1 = "function _Xx8(s) {var _GUk3 = new Date();_GUk3.setUTCFullYear(\"2003\");if (_GUk3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Xx8(s) {var _GUk3 = new Date();_GUk3.setUTCFullYear(\"2003\");if (_GUk3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _UEn9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}