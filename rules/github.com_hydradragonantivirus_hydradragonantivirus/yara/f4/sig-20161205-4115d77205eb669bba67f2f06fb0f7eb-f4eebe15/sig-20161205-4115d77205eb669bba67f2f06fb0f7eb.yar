rule sig_20161205_4115d77205eb669bba67f2f06fb0f7eb {
  meta:
    description = "datamaliciousorder - file 20161205_4115d77205eb669bba67f2f06fb0f7eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3130b160548867abf1485c216fb2cc5d2e516b986d844feccf709d5fe34e942"

  strings:
    $s1 = "function _Uo9(s) {var _Cn7 = new Date();_Cn7.setUTCFullYear(\"2003\");if (_Cn7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Uo9(s) {var _Cn7 = new Date();_Cn7.setUTCFullYear(\"2003\");if (_Cn7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _ZQp9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}