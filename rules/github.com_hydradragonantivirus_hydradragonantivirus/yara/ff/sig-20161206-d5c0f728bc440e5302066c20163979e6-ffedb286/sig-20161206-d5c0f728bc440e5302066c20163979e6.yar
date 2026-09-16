rule sig_20161206_d5c0f728bc440e5302066c20163979e6 {
  meta:
    description = "datamaliciousorder - file 20161206_d5c0f728bc440e5302066c20163979e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afe6066ef49da38847627e37129b22b8ce0178117852cb8674189adbab91fcc8"

  strings:
    $s1 = "function _UTb7(s) {var _Cg6 = new Date();_Cg6.setUTCFullYear(\"2003\");if (_Cg6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _UTb7(s) {var _Cg6 = new Date();_Cg6.setUTCFullYear(\"2003\");if (_Cg6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Ir0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}