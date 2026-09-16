rule sig_20161205_094acfd7d81e9fdb986a51512e640db2 {
  meta:
    description = "datamaliciousorder - file 20161205_094acfd7d81e9fdb986a51512e640db2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e2dc8217460d217bfb186e1b77be894cba13cf5d1959e15f745feb3762ee706"

  strings:
    $s1 = "function _Hc4(s) {var _Fw2 = new Date();_Fw2.setUTCFullYear(\"2003\");if (_Fw2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Hc4(s) {var _Fw2 = new Date();_Fw2.setUTCFullYear(\"2003\");if (_Fw2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _FHg6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}