rule sig_20161206_ade0422d4d943889ab8872469d4da4e1 {
  meta:
    description = "datamaliciousorder - file 20161206_ade0422d4d943889ab8872469d4da4e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d734b1e2a1c9e866dad3bcf7dd6d1a5fe5dd432bce0919ba554801289e526bb"

  strings:
    $s1 = "function _Yp3(s) {var _FRl4 = new Date();_FRl4.setUTCFullYear(\"2003\");if (_FRl4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Yp3(s) {var _FRl4 = new Date();_FRl4.setUTCFullYear(\"2003\");if (_FRl4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _MTa5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}