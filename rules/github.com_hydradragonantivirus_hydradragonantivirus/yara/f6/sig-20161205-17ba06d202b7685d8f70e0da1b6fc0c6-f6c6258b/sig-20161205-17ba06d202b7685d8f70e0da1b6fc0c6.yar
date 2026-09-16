rule sig_20161205_17ba06d202b7685d8f70e0da1b6fc0c6 {
  meta:
    description = "datamaliciousorder - file 20161205_17ba06d202b7685d8f70e0da1b6fc0c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbe52ac7707b5b3be687a398b0e067ba9ee58a39796123cffd135b1807ff091d"

  strings:
    $s1 = "function _QHb0(s) {var _Rz0 = new Date();_Rz0.setUTCFullYear(\"2003\");if (_Rz0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _QHb0(s) {var _Rz0 = new Date();_Rz0.setUTCFullYear(\"2003\");if (_Rz0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _ILf0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}