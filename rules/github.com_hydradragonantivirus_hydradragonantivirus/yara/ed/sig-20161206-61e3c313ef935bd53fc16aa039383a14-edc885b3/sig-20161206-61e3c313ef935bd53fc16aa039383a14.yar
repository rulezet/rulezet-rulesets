rule sig_20161206_61e3c313ef935bd53fc16aa039383a14 {
  meta:
    description = "datamaliciousorder - file 20161206_61e3c313ef935bd53fc16aa039383a14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e2ec1d2e332f3884c84408312804f364ea20953210c4261bf2418e2d9642fcc"

  strings:
    $s1 = "function _SNp3(s) {var _Bd2 = new Date();_Bd2.setUTCFullYear(\"2003\");if (_Bd2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _SNp3(s) {var _Bd2 = new Date();_Bd2.setUTCFullYear(\"2003\");if (_Bd2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _JZs7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}