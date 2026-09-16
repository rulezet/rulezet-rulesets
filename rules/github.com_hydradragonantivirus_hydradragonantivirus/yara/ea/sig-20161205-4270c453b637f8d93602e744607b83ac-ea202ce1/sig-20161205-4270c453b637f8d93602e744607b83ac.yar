rule sig_20161205_4270c453b637f8d93602e744607b83ac {
  meta:
    description = "datamaliciousorder - file 20161205_4270c453b637f8d93602e744607b83ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4be96fbe91f432b94c69dece96eb5f5d75ee77afdd4e6575cc315486ca49f3fd"

  strings:
    $s1 = "function _ZFw0(s) {var _Iu5 = new Date();_Iu5.setUTCFullYear(\"2003\");if (_Iu5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _ZFw0(s) {var _Iu5 = new Date();_Iu5.setUTCFullYear(\"2003\");if (_Iu5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Ae1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}