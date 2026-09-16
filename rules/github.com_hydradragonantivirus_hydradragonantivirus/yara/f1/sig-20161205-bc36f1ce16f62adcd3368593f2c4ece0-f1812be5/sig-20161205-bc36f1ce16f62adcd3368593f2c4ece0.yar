rule sig_20161205_bc36f1ce16f62adcd3368593f2c4ece0 {
  meta:
    description = "datamaliciousorder - file 20161205_bc36f1ce16f62adcd3368593f2c4ece0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3f7159425c0e6b1c076d12eacb62345188cd9fbc7fb74052a5b3b220df91e2f"

  strings:
    $s1 = "function _Sa8(s) {var _Oa6 = new Date();_Oa6.setUTCFullYear(\"2003\");if (_Oa6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Sa8(s) {var _Oa6 = new Date();_Oa6.setUTCFullYear(\"2003\");if (_Oa6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _HDv5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}