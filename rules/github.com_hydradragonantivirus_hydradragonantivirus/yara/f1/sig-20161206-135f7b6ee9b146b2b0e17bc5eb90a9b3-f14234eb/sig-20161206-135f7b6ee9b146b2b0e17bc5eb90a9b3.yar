rule sig_20161206_135f7b6ee9b146b2b0e17bc5eb90a9b3 {
  meta:
    description = "datamaliciousorder - file 20161206_135f7b6ee9b146b2b0e17bc5eb90a9b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a45e88bb7d8e1d0163510d40832fe9643567066f62c6fd8d0a6f7151a36f98f3"

  strings:
    $s1 = "function _Ns2(s) {var _RRs9 = new Date();_RRs9.setUTCFullYear(\"2003\");if (_RRs9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ns2(s) {var _RRs9 = new Date();_RRs9.setUTCFullYear(\"2003\");if (_RRs9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _IXa0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}