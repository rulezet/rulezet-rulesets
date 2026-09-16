rule sig_20161205_2a2ace7ab8b8d059cc80a5aad05dfe95 {
  meta:
    description = "datamaliciousorder - file 20161205_2a2ace7ab8b8d059cc80a5aad05dfe95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6762113eea2abc07e357c2ca90b4c13c421b45501075d8a0d04888172205a830"

  strings:
    $s1 = "function _AZv0(s) {var _Pe6 = new Date();_Pe6.setUTCFullYear(\"2003\");if (_Pe6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _AZv0(s) {var _Pe6 = new Date();_Pe6.setUTCFullYear(\"2003\");if (_Pe6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _HIr5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}