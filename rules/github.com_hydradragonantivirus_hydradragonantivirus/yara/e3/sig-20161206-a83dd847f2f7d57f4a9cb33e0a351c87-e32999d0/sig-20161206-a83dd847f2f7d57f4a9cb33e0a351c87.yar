rule sig_20161206_a83dd847f2f7d57f4a9cb33e0a351c87 {
  meta:
    description = "datamaliciousorder - file 20161206_a83dd847f2f7d57f4a9cb33e0a351c87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "789807acc0a1d5d8d0e5e9db499d4c53e377b5d0ef69440644566eb2d22bdfc3"

  strings:
    $s1 = "function _VNt3(s) {var _OZo1 = new Date();_OZo1.setUTCFullYear(\"2003\");if (_OZo1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _VNt3(s) {var _OZo1 = new Date();_OZo1.setUTCFullYear(\"2003\");if (_OZo1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _BLw9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}