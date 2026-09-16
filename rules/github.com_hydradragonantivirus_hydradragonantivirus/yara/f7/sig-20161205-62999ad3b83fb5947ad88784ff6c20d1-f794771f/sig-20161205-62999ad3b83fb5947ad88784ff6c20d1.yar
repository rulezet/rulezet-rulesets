rule sig_20161205_62999ad3b83fb5947ad88784ff6c20d1 {
  meta:
    description = "datamaliciousorder - file 20161205_62999ad3b83fb5947ad88784ff6c20d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "177d775ff799fa0a50094506f0cbd43a3205dfe09a3ca1358749b7a954cd8834"

  strings:
    $s1 = "function _TNp1(s) {var _Ri6 = new Date();_Ri6.setUTCFullYear(\"2003\");if (_Ri6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _TNp1(s) {var _Ri6 = new Date();_Ri6.setUTCFullYear(\"2003\");if (_Ri6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Gd3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}