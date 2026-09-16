rule sig_20161205_0cf84d5a6e27eacd5693b782d3dac5e8 {
  meta:
    description = "datamaliciousorder - file 20161205_0cf84d5a6e27eacd5693b782d3dac5e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d0b3ea63fbce3a4dfd4b266faebf79017624c202ce4fe14f37203430cb400f6"

  strings:
    $s1 = "function _Th3(s) {var _FNi0 = new Date();_FNi0.setUTCFullYear(\"2003\");if (_FNi0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Th3(s) {var _FNi0 = new Date();_FNi0.setUTCFullYear(\"2003\");if (_FNi0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _UXc7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}