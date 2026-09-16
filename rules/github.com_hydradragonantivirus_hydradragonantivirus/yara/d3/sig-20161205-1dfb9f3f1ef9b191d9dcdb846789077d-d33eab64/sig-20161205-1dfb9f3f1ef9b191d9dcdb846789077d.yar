rule sig_20161205_1dfb9f3f1ef9b191d9dcdb846789077d {
  meta:
    description = "datamaliciousorder - file 20161205_1dfb9f3f1ef9b191d9dcdb846789077d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7903a67757f2a1a35f98e399842a738caf740255829cef57d5b2f4b3c00e78d"

  strings:
    $s1 = "function _Sy1(s) {var _ZKf6 = new Date();_ZKf6.setUTCFullYear(\"2003\");if (_ZKf6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Sy1(s) {var _ZKf6 = new Date();_ZKf6.setUTCFullYear(\"2003\");if (_ZKf6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _XJk9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}