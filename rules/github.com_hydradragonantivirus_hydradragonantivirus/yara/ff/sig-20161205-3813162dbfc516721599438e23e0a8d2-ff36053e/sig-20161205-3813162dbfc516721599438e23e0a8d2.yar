rule sig_20161205_3813162dbfc516721599438e23e0a8d2 {
  meta:
    description = "datamaliciousorder - file 20161205_3813162dbfc516721599438e23e0a8d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95cb296562f9dc86ac8eefcde5f00f7dd386cea25286ec8b8203c17ed1205b31"

  strings:
    $s1 = "function _Ci8(s) {var _Uf6 = new Date();_Uf6.setUTCFullYear(\"2003\");if (_Uf6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ci8(s) {var _Uf6 = new Date();_Uf6.setUTCFullYear(\"2003\");if (_Uf6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Lu5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}