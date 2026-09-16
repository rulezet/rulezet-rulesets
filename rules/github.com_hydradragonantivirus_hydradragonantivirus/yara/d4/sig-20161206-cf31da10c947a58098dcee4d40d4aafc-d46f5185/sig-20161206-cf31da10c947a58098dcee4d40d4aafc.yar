rule sig_20161206_cf31da10c947a58098dcee4d40d4aafc {
  meta:
    description = "datamaliciousorder - file 20161206_cf31da10c947a58098dcee4d40d4aafc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f4fc90920a7f5df8745265441992fdd9781434009f1c8ad746b1335d0bc902b"

  strings:
    $s1 = "function _CRa1(s) {var _Ew4 = new Date();_Ew4.setUTCFullYear(\"2003\");if (_Ew4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _CRa1(s) {var _Ew4 = new Date();_Ew4.setUTCFullYear(\"2003\");if (_Ew4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _UNe6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}