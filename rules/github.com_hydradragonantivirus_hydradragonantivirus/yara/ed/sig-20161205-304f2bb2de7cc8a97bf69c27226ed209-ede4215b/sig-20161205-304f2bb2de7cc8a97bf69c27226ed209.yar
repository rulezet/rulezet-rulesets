rule sig_20161205_304f2bb2de7cc8a97bf69c27226ed209 {
  meta:
    description = "datamaliciousorder - file 20161205_304f2bb2de7cc8a97bf69c27226ed209.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53cd57483f75deeb6bae49a26b10f40b738fe11c3f21fb0059d520e3fab86b8e"

  strings:
    $s1 = "function _VMo9(s) {var _Al0 = new Date();_Al0.setUTCFullYear(\"2003\");if (_Al0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _VMo9(s) {var _Al0 = new Date();_Al0.setUTCFullYear(\"2003\");if (_Al0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _WGs5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}