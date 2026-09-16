rule sig_20161206_aa2176363eb4bd4504b777d4336791fd {
  meta:
    description = "datamaliciousorder - file 20161206_aa2176363eb4bd4504b777d4336791fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "624a36e4733b9d69c307e74a4ed79d2b8d1440a1330b9aae54463ab139d22895"

  strings:
    $s1 = "function _Rq2(s) {var _THr4 = new Date();_THr4.setUTCFullYear(\"2003\");if (_THr4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Rq2(s) {var _THr4 = new Date();_THr4.setUTCFullYear(\"2003\");if (_THr4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Cu2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}