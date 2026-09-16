rule sig_20161206_5d43d4fc8ce0de8b29c1c2d5773919ee {
  meta:
    description = "datamaliciousorder - file 20161206_5d43d4fc8ce0de8b29c1c2d5773919ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "147adb4db7227cde521ac1055171569ccd392c53840ee7923dfa8675432b3bf0"

  strings:
    $s1 = "function _Uz5(s) {var _Ay3 = new Date();_Ay3.setUTCFullYear(\"2003\");if (_Ay3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Uz5(s) {var _Ay3 = new Date();_Ay3.setUTCFullYear(\"2003\");if (_Ay3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Ph2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}