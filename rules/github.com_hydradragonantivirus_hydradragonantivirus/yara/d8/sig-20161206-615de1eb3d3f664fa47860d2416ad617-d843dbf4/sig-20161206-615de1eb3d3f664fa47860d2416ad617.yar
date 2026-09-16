rule sig_20161206_615de1eb3d3f664fa47860d2416ad617 {
  meta:
    description = "datamaliciousorder - file 20161206_615de1eb3d3f664fa47860d2416ad617.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "163ba04d3c81c3014d23fd5a78b8c22afa53f280da85f44d4239151786da929c"

  strings:
    $s1 = "function _VAp3(s) {var _Gz4 = new Date();_Gz4.setUTCFullYear(\"2003\");if (_Gz4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _VAp3(s) {var _Gz4 = new Date();_Gz4.setUTCFullYear(\"2003\");if (_Gz4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _TOj3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}