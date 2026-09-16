rule sig_20161205_c7854956a3ddf8c7848f35c31f4e1d34 {
  meta:
    description = "datamaliciousorder - file 20161205_c7854956a3ddf8c7848f35c31f4e1d34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88dd2bd061883512afa69d5dad27a6f818d36a8d5c61686625c1300ff1114de6"

  strings:
    $s1 = "function _Ke7(s) {var _VLu5 = new Date();_VLu5.setUTCFullYear(\"2003\");if (_VLu5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ke7(s) {var _VLu5 = new Date();_VLu5.setUTCFullYear(\"2003\");if (_VLu5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Oe4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}