rule sig_20161205_f0bc8f20d5f85c830038d54164086f66 {
  meta:
    description = "datamaliciousorder - file 20161205_f0bc8f20d5f85c830038d54164086f66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1b81f1e55d640cde0065b8c30b68e63619963c00d23f6b4108d150f854680d1"

  strings:
    $s1 = "function _WYu2(s) {var _DLo1 = new Date();_DLo1.setUTCFullYear(\"2003\");if (_DLo1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _WYu2(s) {var _DLo1 = new Date();_DLo1.setUTCFullYear(\"2003\");if (_DLo1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _JSg7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}