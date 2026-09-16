rule sig_20161205_4dad96a6489b67a2b8ee5b2ca38fb449 {
  meta:
    description = "datamaliciousorder - file 20161205_4dad96a6489b67a2b8ee5b2ca38fb449.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ecf8c74be8be6c8285df3f5ddf47de290334ad4a3fb123d9bfb05bebb810c22"

  strings:
    $s1 = "function _WPq4(s) {var _Of6 = new Date();_Of6.setUTCFullYear(\"2003\");if (_Of6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _WPq4(s) {var _Of6 = new Date();_Of6.setUTCFullYear(\"2003\");if (_Of6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _IBn0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}