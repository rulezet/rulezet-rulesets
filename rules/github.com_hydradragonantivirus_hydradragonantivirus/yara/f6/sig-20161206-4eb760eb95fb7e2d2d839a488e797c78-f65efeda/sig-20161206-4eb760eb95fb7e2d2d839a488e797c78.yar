rule sig_20161206_4eb760eb95fb7e2d2d839a488e797c78 {
  meta:
    description = "datamaliciousorder - file 20161206_4eb760eb95fb7e2d2d839a488e797c78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97235233ebb49b552981a11fff266ab3fbbf92ac60e105242a6e72e7b36c2e5a"

  strings:
    $s1 = "function _IZd4(s) {var _TKh9 = new Date();_TKh9.setUTCFullYear(\"2003\");if (_TKh9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _IZd4(s) {var _TKh9 = new Date();_TKh9.setUTCFullYear(\"2003\");if (_TKh9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _CGm1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}