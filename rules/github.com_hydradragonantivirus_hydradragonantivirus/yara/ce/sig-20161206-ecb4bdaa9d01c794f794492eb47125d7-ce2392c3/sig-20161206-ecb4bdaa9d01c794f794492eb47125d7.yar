rule sig_20161206_ecb4bdaa9d01c794f794492eb47125d7 {
  meta:
    description = "datamaliciousorder - file 20161206_ecb4bdaa9d01c794f794492eb47125d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cd3f89fcbe5f0b6543de468c3b4a7b4a0995e4f2f7732afffeba0cd37002749"

  strings:
    $s1 = "function _MIz3(s) {var _Iv0 = new Date();_Iv0.setUTCFullYear(\"2003\");if (_Iv0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _MIz3(s) {var _Iv0 = new Date();_Iv0.setUTCFullYear(\"2003\");if (_Iv0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _QSl8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}