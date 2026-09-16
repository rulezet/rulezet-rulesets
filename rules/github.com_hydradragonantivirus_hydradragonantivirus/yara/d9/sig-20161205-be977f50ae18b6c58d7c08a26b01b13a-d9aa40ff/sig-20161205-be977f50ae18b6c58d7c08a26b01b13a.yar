rule sig_20161205_be977f50ae18b6c58d7c08a26b01b13a {
  meta:
    description = "datamaliciousorder - file 20161205_be977f50ae18b6c58d7c08a26b01b13a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0f1d77bb80e97f8489e8c0c81ba3b4b46e28452692d518be8c83f89e86c9ae9"

  strings:
    $s1 = "function _BEl2(s) {var _HLw7 = new Date();_HLw7.setUTCFullYear(\"2003\");if (_HLw7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _BEl2(s) {var _HLw7 = new Date();_HLw7.setUTCFullYear(\"2003\");if (_HLw7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _SZn3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}