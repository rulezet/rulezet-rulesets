rule sig_20161206_c0b26dffda509a64da59285294421007 {
  meta:
    description = "datamaliciousorder - file 20161206_c0b26dffda509a64da59285294421007.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa4e011940bb1887f147ddd9f2d8804ab1e6c7f18079d01f5eb92baec85d1fb9"

  strings:
    $s1 = "function _GNl1(s) {var _Ql2 = new Date();_Ql2.setUTCFullYear(\"2003\");if (_Ql2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _GNl1(s) {var _Ql2 = new Date();_Ql2.setUTCFullYear(\"2003\");if (_Ql2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Os7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}