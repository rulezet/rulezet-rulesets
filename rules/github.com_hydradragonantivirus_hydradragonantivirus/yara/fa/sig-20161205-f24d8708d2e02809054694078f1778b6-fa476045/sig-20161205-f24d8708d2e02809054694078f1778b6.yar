rule sig_20161205_f24d8708d2e02809054694078f1778b6 {
  meta:
    description = "datamaliciousorder - file 20161205_f24d8708d2e02809054694078f1778b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "014d9e085303989ebad49085177f0fb177bdc00f5e483f1625195d117b1d386e"

  strings:
    $s1 = "function _Vs2(s) {var _Jj6 = new Date();_Jj6.setUTCFullYear(\"2003\");if (_Jj6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Vs2(s) {var _Jj6 = new Date();_Jj6.setUTCFullYear(\"2003\");if (_Jj6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _EJl2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}