rule sig_20161206_fed64225731b8564cf1a86236e482337 {
  meta:
    description = "datamaliciousorder - file 20161206_fed64225731b8564cf1a86236e482337.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fc9da3b8cd1c0ebfc4f8b16d083e9741fb1d798655304d349b2c6523a6fd337"

  strings:
    $s1 = "function _EOm9(s) {var _YZc3 = new Date();_YZc3.setUTCFullYear(\"2003\");if (_YZc3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _EOm9(s) {var _YZc3 = new Date();_YZc3.setUTCFullYear(\"2003\");if (_YZc3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Rk0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}