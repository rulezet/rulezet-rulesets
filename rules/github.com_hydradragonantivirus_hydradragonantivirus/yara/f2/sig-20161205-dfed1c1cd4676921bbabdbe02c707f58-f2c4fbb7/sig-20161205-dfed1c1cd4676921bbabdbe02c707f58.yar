rule sig_20161205_dfed1c1cd4676921bbabdbe02c707f58 {
  meta:
    description = "datamaliciousorder - file 20161205_dfed1c1cd4676921bbabdbe02c707f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f5d74bd0e6bd751ae41bcefe3a4130c8749a6b4040f98bc8e18a3e1281d90b5"

  strings:
    $s1 = "function _NWz8(s) {var _FWa0 = new Date();_FWa0.setUTCFullYear(\"2003\");if (_FWa0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _NWz8(s) {var _FWa0 = new Date();_FWa0.setUTCFullYear(\"2003\");if (_FWa0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ql4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}