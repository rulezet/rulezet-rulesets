rule sig_20161206_ab9e92905b6db45d9a1040cb67e1bf8a {
  meta:
    description = "datamaliciousorder - file 20161206_ab9e92905b6db45d9a1040cb67e1bf8a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6508540ca7aea41deae0789595f93f80a1595850616f3ac3acc052db22d07e1"

  strings:
    $s1 = "function _Ou6(s) {var _TMn8 = new Date();_TMn8.setUTCFullYear(\"2003\");if (_TMn8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ou6(s) {var _TMn8 = new Date();_TMn8.setUTCFullYear(\"2003\");if (_TMn8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Gh8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}