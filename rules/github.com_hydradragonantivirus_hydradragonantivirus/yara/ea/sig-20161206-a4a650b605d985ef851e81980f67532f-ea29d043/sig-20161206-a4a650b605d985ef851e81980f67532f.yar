rule sig_20161206_a4a650b605d985ef851e81980f67532f {
  meta:
    description = "datamaliciousorder - file 20161206_a4a650b605d985ef851e81980f67532f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d7b298fe5925c202b09d4fd7bcee53c209780ade3a1823f0a75a70894a292b3"

  strings:
    $s1 = "function _MQb1(s) {var _Ju4 = new Date();_Ju4.setUTCFullYear(\"2003\");if (_Ju4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _MQb1(s) {var _Ju4 = new Date();_Ju4.setUTCFullYear(\"2003\");if (_Ju4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Pg9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}