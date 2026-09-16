rule sig_20161205_e6efa392712fe75ba2f4d68341a6a701 {
  meta:
    description = "datamaliciousorder - file 20161205_e6efa392712fe75ba2f4d68341a6a701.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c2470ec5c4f4cf7bd8aa004cd97a48d92c41f6ec9fe6799f82a31723b5b1b33"

  strings:
    $s1 = "function _UHb7(s) {var _WBa1 = new Date();_WBa1.setUTCFullYear(\"2003\");if (_WBa1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _UHb7(s) {var _WBa1 = new Date();_WBa1.setUTCFullYear(\"2003\");if (_WBa1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Wt2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}