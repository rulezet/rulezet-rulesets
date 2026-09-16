rule sig_20161205_f7243bcc0d762f1d582d88f5ac30a3f1 {
  meta:
    description = "datamaliciousorder - file 20161205_f7243bcc0d762f1d582d88f5ac30a3f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d487739b5dae62175cba687c888773d3085b6003810ee9c3e7ebaccfee4c6dba"

  strings:
    $s1 = "function _VYe1(s) {var _LIw8 = new Date();_LIw8.setUTCFullYear(\"2003\");if (_LIw8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _VYe1(s) {var _LIw8 = new Date();_LIw8.setUTCFullYear(\"2003\");if (_LIw8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _LXk3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}