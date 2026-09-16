rule sig_20161205_be0dbea2751b66c81b409928f32d6ab2 {
  meta:
    description = "datamaliciousorder - file 20161205_be0dbea2751b66c81b409928f32d6ab2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dce1d1311b47988e584e0bffab8244b0624436feb476160e5890af72676eabc5"

  strings:
    $s1 = "function _Ts0(s) {var _Ia1 = new Date();_Ia1.setUTCFullYear(\"2003\");if (_Ia1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ts0(s) {var _Ia1 = new Date();_Ia1.setUTCFullYear(\"2003\");if (_Ia1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Av4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}