rule sig_20161205_0d8721ba858f62bab70a8b6845f0925b {
  meta:
    description = "datamaliciousorder - file 20161205_0d8721ba858f62bab70a8b6845f0925b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9dc4f4017f2064fdc51063759563aa07c8db031e59c9bec3780cb6abc1fc5b09"

  strings:
    $s1 = "function _Qp4(s) {var _JTx1 = new Date();_JTx1.setUTCFullYear(\"2003\");if (_JTx1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Qp4(s) {var _JTx1 = new Date();_JTx1.setUTCFullYear(\"2003\");if (_JTx1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _OCt7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}