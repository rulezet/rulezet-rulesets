rule sig_20161206_e4b66849cee3a31ad1f57c2db92a4d2e {
  meta:
    description = "datamaliciousorder - file 20161206_e4b66849cee3a31ad1f57c2db92a4d2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "693301d5c2fa7bfa157733d4cf342499adea7d942fb44197e4dfb7dfd296b046"

  strings:
    $s1 = "function _Aq4(s) {var _WNc6 = new Date();_WNc6.setUTCFullYear(\"2003\");if (_WNc6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Aq4(s) {var _WNc6 = new Date();_WNc6.setUTCFullYear(\"2003\");if (_WNc6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Hb0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}