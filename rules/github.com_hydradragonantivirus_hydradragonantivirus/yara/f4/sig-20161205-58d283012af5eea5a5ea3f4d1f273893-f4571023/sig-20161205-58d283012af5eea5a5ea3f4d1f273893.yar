rule sig_20161205_58d283012af5eea5a5ea3f4d1f273893 {
  meta:
    description = "datamaliciousorder - file 20161205_58d283012af5eea5a5ea3f4d1f273893.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d78792d1a7e8c2509c5b31c0b8ba8ae8e0f0fa3b41a3c8349791fd870c1c391a"

  strings:
    $s1 = "function _Xs7(s) {var _Dz1 = new Date();_Dz1.setUTCFullYear(\"2003\");if (_Dz1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Xs7(s) {var _Dz1 = new Date();_Dz1.setUTCFullYear(\"2003\");if (_Dz1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Vq8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}