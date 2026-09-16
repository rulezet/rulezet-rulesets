rule sig_20161206_ab547f7fce7ee974cc6828e156e129ed {
  meta:
    description = "datamaliciousorder - file 20161206_ab547f7fce7ee974cc6828e156e129ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4cc2990ec85dbfb0dec1fdf2819af2825a8fc76db7b2f75e285ddaa13273db3"

  strings:
    $s1 = "function _EPy8(s) {var _Rx9 = new Date();_Rx9.setUTCFullYear(\"2003\");if (_Rx9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _EPy8(s) {var _Rx9 = new Date();_Rx9.setUTCFullYear(\"2003\");if (_Rx9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _LFr5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}