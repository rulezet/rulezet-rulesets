rule sig_20161205_4a94d993ad95260ef2ac2a7b0c4c1ea0 {
  meta:
    description = "datamaliciousorder - file 20161205_4a94d993ad95260ef2ac2a7b0c4c1ea0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b2ec505d99facbcfd65ccc1c374f02d98858b238f973e1eaaf97cfa8cfc3b41"

  strings:
    $s1 = "function _Yu7(s) {var _QWo9 = new Date();_QWo9.setUTCFullYear(\"2003\");if (_QWo9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Yu7(s) {var _QWo9 = new Date();_QWo9.setUTCFullYear(\"2003\");if (_QWo9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Dc7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}