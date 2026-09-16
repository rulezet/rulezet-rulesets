rule sig_20161205_3f130353bc2edb9ad8effb4da5e23f6d {
  meta:
    description = "datamaliciousorder - file 20161205_3f130353bc2edb9ad8effb4da5e23f6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02d3336dc8f9d8695240801547d155fadbfc4a80c20bac4f7d1287adfcd49eba"

  strings:
    $s1 = "function _GSx8(s) {var _ACq4 = new Date();_ACq4.setUTCFullYear(\"2003\");if (_ACq4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _GSx8(s) {var _ACq4 = new Date();_ACq4.setUTCFullYear(\"2003\");if (_ACq4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _KLh6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}