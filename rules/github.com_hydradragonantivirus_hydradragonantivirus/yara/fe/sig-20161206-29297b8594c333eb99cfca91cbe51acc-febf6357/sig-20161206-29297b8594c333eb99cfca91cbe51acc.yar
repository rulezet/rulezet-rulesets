rule sig_20161206_29297b8594c333eb99cfca91cbe51acc {
  meta:
    description = "datamaliciousorder - file 20161206_29297b8594c333eb99cfca91cbe51acc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b41e929007cfff12aa3fd40948a6daf0d0781eab066598f79930de0a5a0400c6"

  strings:
    $s1 = "function _Rt4(s) {var _Ii0 = new Date();_Ii0.setUTCFullYear(\"2003\");if (_Ii0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Rt4(s) {var _Ii0 = new Date();_Ii0.setUTCFullYear(\"2003\");if (_Ii0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Ex5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}