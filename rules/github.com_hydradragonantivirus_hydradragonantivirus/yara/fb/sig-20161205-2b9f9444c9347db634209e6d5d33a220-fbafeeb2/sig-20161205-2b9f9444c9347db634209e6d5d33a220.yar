rule sig_20161205_2b9f9444c9347db634209e6d5d33a220 {
  meta:
    description = "datamaliciousorder - file 20161205_2b9f9444c9347db634209e6d5d33a220.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4bc3f66150785c992330177c75684b02ce8f3539aa3b63383ea7ebef5d87bfc"

  strings:
    $s1 = "function _Rt6(s) {var _PGi7 = new Date();_PGi7.setUTCFullYear(\"2003\");if (_PGi7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Rt6(s) {var _PGi7 = new Date();_PGi7.setUTCFullYear(\"2003\");if (_PGi7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _ZMe9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}