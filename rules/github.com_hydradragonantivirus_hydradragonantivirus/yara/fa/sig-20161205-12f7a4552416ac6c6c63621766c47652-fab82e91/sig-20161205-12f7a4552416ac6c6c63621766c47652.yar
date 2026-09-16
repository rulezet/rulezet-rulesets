rule sig_20161205_12f7a4552416ac6c6c63621766c47652 {
  meta:
    description = "datamaliciousorder - file 20161205_12f7a4552416ac6c6c63621766c47652.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66e795cb121335c6addc894736bfc4573948d1dc348d08cb461e81dd7c3a814b"

  strings:
    $s1 = "function _OSk3(s) {var _XWx2 = new Date();_XWx2.setUTCFullYear(\"2003\");if (_XWx2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _OSk3(s) {var _XWx2 = new Date();_XWx2.setUTCFullYear(\"2003\");if (_XWx2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ie5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}