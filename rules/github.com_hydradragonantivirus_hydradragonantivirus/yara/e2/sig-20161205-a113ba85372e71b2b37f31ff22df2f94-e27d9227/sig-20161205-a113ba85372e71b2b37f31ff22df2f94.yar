rule sig_20161205_a113ba85372e71b2b37f31ff22df2f94 {
  meta:
    description = "datamaliciousorder - file 20161205_a113ba85372e71b2b37f31ff22df2f94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db6c0d4b1bb988dfbadb2488b7dc54398239342169d5160cd398a09b7dff5505"

  strings:
    $s1 = "function _Yy0(s) {var _Fe6 = new Date();_Fe6.setUTCFullYear(\"2003\");if (_Fe6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Yy0(s) {var _Fe6 = new Date();_Fe6.setUTCFullYear(\"2003\");if (_Fe6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _PYl5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}