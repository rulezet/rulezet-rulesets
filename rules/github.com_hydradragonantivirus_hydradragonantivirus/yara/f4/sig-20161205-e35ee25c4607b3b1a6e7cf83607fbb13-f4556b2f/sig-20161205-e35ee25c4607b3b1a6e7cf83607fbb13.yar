rule sig_20161205_e35ee25c4607b3b1a6e7cf83607fbb13 {
  meta:
    description = "datamaliciousorder - file 20161205_e35ee25c4607b3b1a6e7cf83607fbb13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd5b195913ccd6d66f1fc71c5c8be0936e22bbc1ca8864424d22cf2911b635fe"

  strings:
    $s1 = "function _Fg3(s) {var _LSu3 = new Date();_LSu3.setUTCFullYear(\"2003\");if (_LSu3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Fg3(s) {var _LSu3 = new Date();_LSu3.setUTCFullYear(\"2003\");if (_LSu3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _DAi1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}