rule sig_20161205_b62c20a9a006700e1b566db704cc34e2 {
  meta:
    description = "datamaliciousorder - file 20161205_b62c20a9a006700e1b566db704cc34e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aaeed7dccd129f9728e4c3bc080e917d90f3ee8e9ca3df25bcb063b250ac8acb"

  strings:
    $s1 = "function _EJm4(s) {var _AOi6 = new Date();_AOi6.setUTCFullYear(\"2003\");if (_AOi6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _EJm4(s) {var _AOi6 = new Date();_AOi6.setUTCFullYear(\"2003\");if (_AOi6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Bn6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}