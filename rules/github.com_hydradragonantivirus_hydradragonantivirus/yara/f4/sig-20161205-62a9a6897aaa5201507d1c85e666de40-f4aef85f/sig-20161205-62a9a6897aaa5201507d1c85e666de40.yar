rule sig_20161205_62a9a6897aaa5201507d1c85e666de40 {
  meta:
    description = "datamaliciousorder - file 20161205_62a9a6897aaa5201507d1c85e666de40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a18687de59ae5f1cce6857d3058a763a4d004e43bea727eee9ddf15a05c0a8ed"

  strings:
    $s1 = "function _WPr4(s) {var _Hy4 = new Date();_Hy4.setUTCFullYear(\"2003\");if (_Hy4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _WPr4(s) {var _Hy4 = new Date();_Hy4.setUTCFullYear(\"2003\");if (_Hy4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Uh1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}