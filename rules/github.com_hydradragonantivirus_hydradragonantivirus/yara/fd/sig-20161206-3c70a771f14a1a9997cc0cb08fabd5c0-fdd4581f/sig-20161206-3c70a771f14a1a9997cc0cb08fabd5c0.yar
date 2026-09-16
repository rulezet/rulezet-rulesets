rule sig_20161206_3c70a771f14a1a9997cc0cb08fabd5c0 {
  meta:
    description = "datamaliciousorder - file 20161206_3c70a771f14a1a9997cc0cb08fabd5c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b853d647aaa5897a90cf169e4fd6c25872c952ff82558879f36cbe576ac1be8"

  strings:
    $s1 = "function _NXc2(s) {var _UQh2 = new Date();_UQh2.setUTCFullYear(\"2003\");if (_UQh2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _NXc2(s) {var _UQh2 = new Date();_UQh2.setUTCFullYear(\"2003\");if (_UQh2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Yx4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}