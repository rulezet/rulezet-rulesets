rule sig_20161206_a600ca8c4edc1fbb237a3ea852346449 {
  meta:
    description = "datamaliciousorder - file 20161206_a600ca8c4edc1fbb237a3ea852346449.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5286ab3a7c17801b16b6f54898c44e101e61305b422b3b5a8a400bdea3cb6641"

  strings:
    $s1 = "function _UWr1(s) {var _Vb3 = new Date();_Vb3.setUTCFullYear(\"2003\");if (_Vb3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _UWr1(s) {var _Vb3 = new Date();_Vb3.setUTCFullYear(\"2003\");if (_Vb3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _FIs8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}