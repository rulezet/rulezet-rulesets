rule sig_20161205_edfc6e082a76736bacae875fe3dcf7c5 {
  meta:
    description = "datamaliciousorder - file 20161205_edfc6e082a76736bacae875fe3dcf7c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce28535b097971b1ba537f3bf936a41a52697c2bd21347cd1f3de72f8f85a91c"

  strings:
    $s1 = "function _Mw1(s) {var _OGa7 = new Date();_OGa7.setUTCFullYear(\"2003\");if (_OGa7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Mw1(s) {var _OGa7 = new Date();_OGa7.setUTCFullYear(\"2003\");if (_OGa7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _DUy2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}