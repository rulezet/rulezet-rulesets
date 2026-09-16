rule sig_20161205_be7a9805649b6b46988155c6362924b9 {
  meta:
    description = "datamaliciousorder - file 20161205_be7a9805649b6b46988155c6362924b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cac064f0c227682071987ca82de206a37270df8f1fa16a3168e9cbf33f5bcbdd"

  strings:
    $s1 = "function _JPa5(s) {var _Yx1 = new Date();_Yx1.setUTCFullYear(\"2003\");if (_Yx1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _JPa5(s) {var _Yx1 = new Date();_Yx1.setUTCFullYear(\"2003\");if (_Yx1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Mg3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}