rule sig_20161205_b787dabf790418b76372bfac6e2e51e3 {
  meta:
    description = "datamaliciousorder - file 20161205_b787dabf790418b76372bfac6e2e51e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5167e38248f2520641d1b2c789b298f180b097d36e441870710180cab698569"

  strings:
    $s1 = "function _On3(s) {var _Nv7 = new Date();_Nv7.setUTCFullYear(\"2003\");if (_Nv7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _On3(s) {var _Nv7 = new Date();_Nv7.setUTCFullYear(\"2003\");if (_Nv7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Ub7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}