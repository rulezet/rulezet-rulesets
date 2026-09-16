rule sig_20161205_8df6cdd9cf952893183ac600deb3bc3a {
  meta:
    description = "datamaliciousorder - file 20161205_8df6cdd9cf952893183ac600deb3bc3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bff2e13f364049da8d9161e6c9057fe577e6d38b61afbf22fe1abb1d291f57d6"

  strings:
    $s1 = "function _LAn7(s) {var _Ki7 = new Date();_Ki7.setUTCFullYear(\"2003\");if (_Ki7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _LAn7(s) {var _Ki7 = new Date();_Ki7.setUTCFullYear(\"2003\");if (_Ki7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Cu4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}