rule sig_20161206_b25433457be02e25a381a60673959030 {
  meta:
    description = "datamaliciousorder - file 20161206_b25433457be02e25a381a60673959030.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96e533ce3d82c303ae3860e83e3f88b110ee7391532526312c24079d0cced4bf"

  strings:
    $s1 = "function _OUr8(s) {var _Wy5 = new Date();_Wy5.setUTCFullYear(\"2003\");if (_Wy5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _OUr8(s) {var _Wy5 = new Date();_Wy5.setUTCFullYear(\"2003\");if (_Wy5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _HEt0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}