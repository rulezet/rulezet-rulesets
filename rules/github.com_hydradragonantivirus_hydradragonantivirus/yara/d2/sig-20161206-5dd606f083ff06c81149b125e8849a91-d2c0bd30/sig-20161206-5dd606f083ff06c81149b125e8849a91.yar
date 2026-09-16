rule sig_20161206_5dd606f083ff06c81149b125e8849a91 {
  meta:
    description = "datamaliciousorder - file 20161206_5dd606f083ff06c81149b125e8849a91.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dd3733560caa8f8baa88556e87d95a2eb4f956cbb39fddca32090d9ad09d5e2"

  strings:
    $s1 = "function _Sp5(s) {var _COh8 = new Date();_COh8.setUTCFullYear(\"2003\");if (_COh8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Sp5(s) {var _COh8 = new Date();_COh8.setUTCFullYear(\"2003\");if (_COh8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _HYx1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}