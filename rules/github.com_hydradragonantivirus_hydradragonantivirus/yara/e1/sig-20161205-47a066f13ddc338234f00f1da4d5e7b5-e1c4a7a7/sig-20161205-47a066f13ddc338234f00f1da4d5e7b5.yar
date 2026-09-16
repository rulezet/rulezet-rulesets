rule sig_20161205_47a066f13ddc338234f00f1da4d5e7b5 {
  meta:
    description = "datamaliciousorder - file 20161205_47a066f13ddc338234f00f1da4d5e7b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2a66672d04b317116fc1c1b8a53c1dcf3b0a7ed03b9149d50e94eab9088b323"

  strings:
    $s1 = "function _HHv7(s) {var _Jb0 = new Date();_Jb0.setUTCFullYear(\"2003\");if (_Jb0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _HHv7(s) {var _Jb0 = new Date();_Jb0.setUTCFullYear(\"2003\");if (_Jb0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _VPw0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}