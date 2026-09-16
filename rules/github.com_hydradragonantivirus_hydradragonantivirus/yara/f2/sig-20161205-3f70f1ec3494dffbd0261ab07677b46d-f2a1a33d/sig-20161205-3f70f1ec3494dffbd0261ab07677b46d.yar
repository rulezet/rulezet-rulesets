rule sig_20161205_3f70f1ec3494dffbd0261ab07677b46d {
  meta:
    description = "datamaliciousorder - file 20161205_3f70f1ec3494dffbd0261ab07677b46d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b1b4d886f6cd4c7a6620e81e761b97be572fb3ce6321c4f191e4a95c7fc0d65"

  strings:
    $s1 = "function _AXt9(s) {var _Gl1 = new Date();_Gl1.setUTCFullYear(\"2003\");if (_Gl1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _AXt9(s) {var _Gl1 = new Date();_Gl1.setUTCFullYear(\"2003\");if (_Gl1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _UDv8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}