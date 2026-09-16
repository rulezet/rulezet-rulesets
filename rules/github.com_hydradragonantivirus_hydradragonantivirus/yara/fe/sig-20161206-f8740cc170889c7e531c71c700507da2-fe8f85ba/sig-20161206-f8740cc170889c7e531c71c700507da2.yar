rule sig_20161206_f8740cc170889c7e531c71c700507da2 {
  meta:
    description = "datamaliciousorder - file 20161206_f8740cc170889c7e531c71c700507da2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e7e823975f2b4b044cacdeb823108723212c9d7bb574743d406985976718527"

  strings:
    $s1 = "function _Bp7(s) {var _SVa3 = new Date();_SVa3.setUTCFullYear(\"2003\");if (_SVa3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Bp7(s) {var _SVa3 = new Date();_SVa3.setUTCFullYear(\"2003\");if (_SVa3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ii0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}