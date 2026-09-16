rule sig_20161205_f3fec8e8d5b6766081784881f9b7a0b8 {
  meta:
    description = "datamaliciousorder - file 20161205_f3fec8e8d5b6766081784881f9b7a0b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd909685a3ac7c5b6a5befc0aaf7c336b7741c19eac02a0745a6bac97f5d1afc"

  strings:
    $s1 = "function _HWv5(s) {var _HMt0 = new Date();_HMt0.setUTCFullYear(\"2003\");if (_HMt0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _HWv5(s) {var _HMt0 = new Date();_HMt0.setUTCFullYear(\"2003\");if (_HMt0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _XGx8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}