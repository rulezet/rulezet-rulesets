rule sig_20161205_8e75898002ce11cc0d00bbeca9efe1af {
  meta:
    description = "datamaliciousorder - file 20161205_8e75898002ce11cc0d00bbeca9efe1af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "154e9454f730fe67cecf205e00974bc60e61cad9038f613d338e0e24738cfdca"

  strings:
    $s1 = "function _Pr2(s) {var _MIc6 = new Date();_MIc6.setUTCFullYear(\"2003\");if (_MIc6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Pr2(s) {var _MIc6 = new Date();_MIc6.setUTCFullYear(\"2003\");if (_MIc6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Qk4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}