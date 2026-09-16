rule sig_20161205_1cd3192cdf6e751a0f224b4605e374f7 {
  meta:
    description = "datamaliciousorder - file 20161205_1cd3192cdf6e751a0f224b4605e374f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1a08602a9c412cbdeed244cf6556f5e2157a5dcee1fa227b2bd5a7f9c101c13"

  strings:
    $s1 = "function _IOr8(s) {var _VMb0 = new Date();_VMb0.setUTCFullYear(\"2003\");if (_VMb0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _IOr8(s) {var _VMb0 = new Date();_VMb0.setUTCFullYear(\"2003\");if (_VMb0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _VZc7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}