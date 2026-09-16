rule sig_20161205_6bdccd52df127a2772d5643ebe12656b {
  meta:
    description = "datamaliciousorder - file 20161205_6bdccd52df127a2772d5643ebe12656b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e69da8b3bd633058a1ec5f41b18aee60c173121c688e1a2562265557373283c4"

  strings:
    $s1 = "function _Gb1(s) {var _Wr1 = new Date();_Wr1.setUTCFullYear(\"2003\");if (_Wr1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Gb1(s) {var _Wr1 = new Date();_Wr1.setUTCFullYear(\"2003\");if (_Wr1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Kq2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}