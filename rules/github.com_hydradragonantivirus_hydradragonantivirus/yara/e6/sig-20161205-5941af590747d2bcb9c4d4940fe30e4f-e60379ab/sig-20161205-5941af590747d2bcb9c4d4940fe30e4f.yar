rule sig_20161205_5941af590747d2bcb9c4d4940fe30e4f {
  meta:
    description = "datamaliciousorder - file 20161205_5941af590747d2bcb9c4d4940fe30e4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0327df627fb13ecf0f6142d0c14d427f66d79c4fd93859b4700f53e304d585d"

  strings:
    $s1 = "function _PId6(s) {var _Up0 = new Date();_Up0.setUTCFullYear(\"2003\");if (_Up0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _PId6(s) {var _Up0 = new Date();_Up0.setUTCFullYear(\"2003\");if (_Up0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Dh8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}