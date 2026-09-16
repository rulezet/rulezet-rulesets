rule sig_20161205_70998620095dd52e4ef907bef98ce9f7 {
  meta:
    description = "datamaliciousorder - file 20161205_70998620095dd52e4ef907bef98ce9f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b632b0c55fcc96d5a17373438bbae4ee5bc02c82741b89f547c5ac8e92811e24"

  strings:
    $s1 = "function _FYy0(s) {var _Kx8 = new Date();_Kx8.setUTCFullYear(\"2003\");if (_Kx8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _FYy0(s) {var _Kx8 = new Date();_Kx8.setUTCFullYear(\"2003\");if (_Kx8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Ln1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}