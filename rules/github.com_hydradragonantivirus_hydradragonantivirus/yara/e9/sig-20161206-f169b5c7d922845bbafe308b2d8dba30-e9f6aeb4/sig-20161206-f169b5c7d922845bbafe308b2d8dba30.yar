rule sig_20161206_f169b5c7d922845bbafe308b2d8dba30 {
  meta:
    description = "datamaliciousorder - file 20161206_f169b5c7d922845bbafe308b2d8dba30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a36f64f63e1e0ab62d6e52194a578999aa01fc8e0f4df4ed38591092218a93b8"

  strings:
    $s1 = "function _BZi8(s) {var _GYx8 = new Date();_GYx8.setUTCFullYear(\"2003\");if (_GYx8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _BZi8(s) {var _GYx8 = new Date();_GYx8.setUTCFullYear(\"2003\");if (_GYx8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Zr6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}