rule sig_20161205_1778e126f48eac663473c0bb6a42c077 {
  meta:
    description = "datamaliciousorder - file 20161205_1778e126f48eac663473c0bb6a42c077.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "055ee1742296073628d6953e37a3c9820e7bb37071cdc6a7c42e87648e439749"

  strings:
    $s1 = "function _TLh0(s) {var _Pi9 = new Date();_Pi9.setUTCFullYear(\"2003\");if (_Pi9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _TLh0(s) {var _Pi9 = new Date();_Pi9.setUTCFullYear(\"2003\");if (_Pi9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Bp9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}