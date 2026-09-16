rule sig_20161205_dfaba27dd7c3b7c171825b2cd1317f02 {
  meta:
    description = "datamaliciousorder - file 20161205_dfaba27dd7c3b7c171825b2cd1317f02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b30bbd747803a5a9cf53074033e42944f722e4153a76d06cbbf4a8c2847ca9d"

  strings:
    $s1 = "function _We6(s) {var _Jv3 = new Date();_Jv3.setUTCFullYear(\"2003\");if (_Jv3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _We6(s) {var _Jv3 = new Date();_Jv3.setUTCFullYear(\"2003\");if (_Jv3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _XAb4(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}