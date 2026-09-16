rule sig_20161205_7d78ae477730b5204f8361e8b12ea24b {
  meta:
    description = "datamaliciousorder - file 20161205_7d78ae477730b5204f8361e8b12ea24b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a77c110e2f3e9f81e7ae96def55622f3a6a03b9710fa04861bb8527fdc83da7"

  strings:
    $s1 = "function _LFy7(s) {var _DYc5 = new Date();_DYc5.setUTCFullYear(\"2003\");if (_DYc5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _LFy7(s) {var _DYc5 = new Date();_DYc5.setUTCFullYear(\"2003\");if (_DYc5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Xy7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}