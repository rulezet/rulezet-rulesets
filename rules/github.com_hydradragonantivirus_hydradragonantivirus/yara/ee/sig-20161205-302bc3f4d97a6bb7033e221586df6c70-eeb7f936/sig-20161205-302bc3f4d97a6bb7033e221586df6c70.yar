rule sig_20161205_302bc3f4d97a6bb7033e221586df6c70 {
  meta:
    description = "datamaliciousorder - file 20161205_302bc3f4d97a6bb7033e221586df6c70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c6217126ee8b2d5082037b095d425f561c6ae0c0bfbf35e9df76388ad9d3e47"

  strings:
    $s1 = "function _Gz9(s) {var _BFk4 = new Date();_BFk4.setUTCFullYear(\"2003\");if (_BFk4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Gz9(s) {var _BFk4 = new Date();_BFk4.setUTCFullYear(\"2003\");if (_BFk4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _FRn8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}