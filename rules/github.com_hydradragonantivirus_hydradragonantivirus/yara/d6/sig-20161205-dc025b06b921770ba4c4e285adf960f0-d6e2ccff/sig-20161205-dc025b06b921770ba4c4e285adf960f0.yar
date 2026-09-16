rule sig_20161205_dc025b06b921770ba4c4e285adf960f0 {
  meta:
    description = "datamaliciousorder - file 20161205_dc025b06b921770ba4c4e285adf960f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff74608b887c5420710a52bdafc0a1d90a48f2228b0801a9ef275e757a378edf"

  strings:
    $s1 = "function _XPh7(s) {var _UZs7 = new Date();_UZs7.setUTCFullYear(\"2003\");if (_UZs7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _XPh7(s) {var _UZs7 = new Date();_UZs7.setUTCFullYear(\"2003\");if (_UZs7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _QNg1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}