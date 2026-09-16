rule sig_20161206_e233a1accc5c964a7a5fb58f12f95330 {
  meta:
    description = "datamaliciousorder - file 20161206_e233a1accc5c964a7a5fb58f12f95330.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dafa5fe44cc93fc79e296ccc1f0c1778e03d56e393c11a01210ba7babce8d39d"

  strings:
    $s1 = "function _Ug2(s) {var _DMq3 = new Date();_DMq3.setUTCFullYear(\"2003\");if (_DMq3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ug2(s) {var _DMq3 = new Date();_DMq3.setUTCFullYear(\"2003\");if (_DMq3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _UQa6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}