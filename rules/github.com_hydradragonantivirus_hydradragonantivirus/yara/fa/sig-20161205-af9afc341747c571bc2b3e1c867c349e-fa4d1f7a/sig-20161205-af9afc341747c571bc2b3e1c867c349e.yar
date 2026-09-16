rule sig_20161205_af9afc341747c571bc2b3e1c867c349e {
  meta:
    description = "datamaliciousorder - file 20161205_af9afc341747c571bc2b3e1c867c349e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bbab91f1c119c5dc848bee7d3480a0cf52a7fefa2f4fa5d6059c4472d53b956"

  strings:
    $s1 = "function _Yx8(s) {var _SQk9 = new Date();_SQk9.setUTCFullYear(\"2003\");if (_SQk9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Yx8(s) {var _SQk9 = new Date();_SQk9.setUTCFullYear(\"2003\");if (_SQk9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Pw6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}