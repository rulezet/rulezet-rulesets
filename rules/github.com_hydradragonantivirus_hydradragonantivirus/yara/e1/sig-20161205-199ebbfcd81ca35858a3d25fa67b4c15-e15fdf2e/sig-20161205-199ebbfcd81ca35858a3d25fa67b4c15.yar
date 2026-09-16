rule sig_20161205_199ebbfcd81ca35858a3d25fa67b4c15 {
  meta:
    description = "datamaliciousorder - file 20161205_199ebbfcd81ca35858a3d25fa67b4c15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "746f63fc2a39a148fbf86290aa60eb66dbe22a8866ae6b75640a3f04c663f877"

  strings:
    $s1 = "function _Gn1(s) {var _Xc9 = new Date();_Xc9.setUTCFullYear(\"2003\");if (_Xc9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Gn1(s) {var _Xc9 = new Date();_Xc9.setUTCFullYear(\"2003\");if (_Xc9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _SPz2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}