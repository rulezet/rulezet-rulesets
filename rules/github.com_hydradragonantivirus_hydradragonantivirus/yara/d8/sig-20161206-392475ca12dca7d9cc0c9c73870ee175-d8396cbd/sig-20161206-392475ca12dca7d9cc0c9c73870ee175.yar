rule sig_20161206_392475ca12dca7d9cc0c9c73870ee175 {
  meta:
    description = "datamaliciousorder - file 20161206_392475ca12dca7d9cc0c9c73870ee175.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88969856c271ba49054abc8a4390c402795e3dcc144d505457aefe6071c6368c"

  strings:
    $s1 = "function _OWg5(s) {var _Ym8 = new Date();_Ym8.setUTCFullYear(\"2003\");if (_Ym8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _OWg5(s) {var _Ym8 = new Date();_Ym8.setUTCFullYear(\"2003\");if (_Ym8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Vo3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}