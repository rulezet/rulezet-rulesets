rule sig_20161205_dc3f2c3e7c36a8a128bac6d5585c24be {
  meta:
    description = "datamaliciousorder - file 20161205_dc3f2c3e7c36a8a128bac6d5585c24be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8251393be9be129d18c7e47b2d42a32986ecc2ec1851d4743f985984a07c04b6"

  strings:
    $s1 = "function _DJe6(s) {var _Ti9 = new Date();_Ti9.setUTCFullYear(\"2003\");if (_Ti9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _DJe6(s) {var _Ti9 = new Date();_Ti9.setUTCFullYear(\"2003\");if (_Ti9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Ln7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}