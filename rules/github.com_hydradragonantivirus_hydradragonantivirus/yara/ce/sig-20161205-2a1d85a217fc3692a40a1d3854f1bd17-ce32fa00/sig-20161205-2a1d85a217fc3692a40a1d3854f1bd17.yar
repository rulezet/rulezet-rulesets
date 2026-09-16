rule sig_20161205_2a1d85a217fc3692a40a1d3854f1bd17 {
  meta:
    description = "datamaliciousorder - file 20161205_2a1d85a217fc3692a40a1d3854f1bd17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bb851748ea0de4a54c1757278b471c714e869f127dad8bd0c41c097eaa58bc2"

  strings:
    $s1 = "function _OFr7(s) {var _En7 = new Date();_En7.setUTCFullYear(\"2003\");if (_En7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _OFr7(s) {var _En7 = new Date();_En7.setUTCFullYear(\"2003\");if (_En7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Oe1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}