rule sig_20161205_90f3bdb5a4cc6b0119bf3886ae6ad4ac {
  meta:
    description = "datamaliciousorder - file 20161205_90f3bdb5a4cc6b0119bf3886ae6ad4ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16e83cf7e537d7cb2f274c641f41ea5fa0baf70ffea23e9a8f561bd649a1b116"

  strings:
    $s1 = "function _Nj5(s) {var _GLn8 = new Date();_GLn8.setUTCFullYear(\"2003\");if (_GLn8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Nj5(s) {var _GLn8 = new Date();_GLn8.setUTCFullYear(\"2003\");if (_GLn8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Of6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}