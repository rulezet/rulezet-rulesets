rule sig_20161206_649e97fec14f4498c32a2271f6ad26ce {
  meta:
    description = "datamaliciousorder - file 20161206_649e97fec14f4498c32a2271f6ad26ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f0281ec760c557a56ca9114b153cceddc74c5431e25a095354db2561f565a44"

  strings:
    $s1 = "function _Ph6(s) {var _Sh9 = new Date();_Sh9.setUTCFullYear(\"2003\");if (_Sh9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ph6(s) {var _Sh9 = new Date();_Sh9.setUTCFullYear(\"2003\");if (_Sh9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _DZs0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}