rule sig_20161205_ca03f61badeed157c48cabd5685c0da0 {
  meta:
    description = "datamaliciousorder - file 20161205_ca03f61badeed157c48cabd5685c0da0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40ba17d9749a1557b46f14735cc96c4d9a392b559a1ac84d439f129506f0686e"

  strings:
    $s1 = "function _QJs8(s) {var _VJz9 = new Date();_VJz9.setUTCFullYear(\"2003\");if (_VJz9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _QJs8(s) {var _VJz9 = new Date();_VJz9.setUTCFullYear(\"2003\");if (_VJz9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _TIb8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}