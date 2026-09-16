rule sig_20161205_64c16a85e7d8059c830219f9a5fbe733 {
  meta:
    description = "datamaliciousorder - file 20161205_64c16a85e7d8059c830219f9a5fbe733.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e63ed30797da661bd08f8ca24720062679f76b17209c9a39df957e5e1c7746b6"

  strings:
    $s1 = "function _GRl0(s) {var _NUs3 = new Date();_NUs3.setUTCFullYear(\"2003\");if (_NUs3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _GRl0(s) {var _NUs3 = new Date();_NUs3.setUTCFullYear(\"2003\");if (_NUs3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _IDk3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}