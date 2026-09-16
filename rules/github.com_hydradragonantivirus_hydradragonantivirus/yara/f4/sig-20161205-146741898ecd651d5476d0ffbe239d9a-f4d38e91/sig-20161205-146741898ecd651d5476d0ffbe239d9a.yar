rule sig_20161205_146741898ecd651d5476d0ffbe239d9a {
  meta:
    description = "datamaliciousorder - file 20161205_146741898ecd651d5476d0ffbe239d9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cee74df52af3b41e07bac72931c4493447d25f28c543441b0b6e7c2aee5c03e7"

  strings:
    $s1 = "function _OWi5(s) {var _EYc9 = new Date();_EYc9.setUTCFullYear(\"2003\");if (_EYc9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _OWi5(s) {var _EYc9 = new Date();_EYc9.setUTCFullYear(\"2003\");if (_EYc9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _RDn6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}