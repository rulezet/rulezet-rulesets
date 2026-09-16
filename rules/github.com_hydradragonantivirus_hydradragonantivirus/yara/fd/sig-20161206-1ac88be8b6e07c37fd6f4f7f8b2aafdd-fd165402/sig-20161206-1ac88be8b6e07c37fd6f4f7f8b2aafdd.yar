rule sig_20161206_1ac88be8b6e07c37fd6f4f7f8b2aafdd {
  meta:
    description = "datamaliciousorder - file 20161206_1ac88be8b6e07c37fd6f4f7f8b2aafdd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abd76bbb2da3ffbed57e78e6d30d29f848a149fdb5c377dd06322d9b1e664fba"

  strings:
    $s1 = "function _PWx2(s) {var _Rc6 = new Date();_Rc6.setUTCFullYear(\"2003\");if (_Rc6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _PWx2(s) {var _Rc6 = new Date();_Rc6.setUTCFullYear(\"2003\");if (_Rc6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Cm3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}