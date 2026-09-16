rule sig_20161206_ae3154ca11cfd88d7be81ba0f134dcf9 {
  meta:
    description = "datamaliciousorder - file 20161206_ae3154ca11cfd88d7be81ba0f134dcf9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50e4513b8d7be1b74da07e02a4c72ae39d4a9732eba3e448e185d420e357543b"

  strings:
    $s1 = "function _KIs0(s) {var _Wg8 = new Date();_Wg8.setUTCFullYear(\"2003\");if (_Wg8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _KIs0(s) {var _Wg8 = new Date();_Wg8.setUTCFullYear(\"2003\");if (_Wg8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Dk7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}