rule sig_20161205_8219d8238e96bf53756546c1a9d5142f {
  meta:
    description = "datamaliciousorder - file 20161205_8219d8238e96bf53756546c1a9d5142f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ada261a2dc51739b2d0dcbba5fe2522cbc39c0581e4882c0bd2098d48833a2c0"

  strings:
    $s1 = "function _QMe7(s) {var _Bq2 = new Date();_Bq2.setUTCFullYear(\"2003\");if (_Bq2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _QMe7(s) {var _Bq2 = new Date();_Bq2.setUTCFullYear(\"2003\");if (_Bq2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _YAx0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}