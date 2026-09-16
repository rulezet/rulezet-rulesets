rule sig_20161205_feba636382ad9a5a7cc129a61920fa2e {
  meta:
    description = "datamaliciousorder - file 20161205_feba636382ad9a5a7cc129a61920fa2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4372ffe0df0a3fcf7a670fa2d1694952ca428f87ec0359ab39d48b4c9dc2255c"

  strings:
    $s1 = "function _VTy1(s) {var _Pi6 = new Date();_Pi6.setUTCFullYear(\"2003\");if (_Pi6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _VTy1(s) {var _Pi6 = new Date();_Pi6.setUTCFullYear(\"2003\");if (_Pi6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _MQq2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}