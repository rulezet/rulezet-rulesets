rule sig_20161205_da186f9b0765edf0fc6d92c76604fda6 {
  meta:
    description = "datamaliciousorder - file 20161205_da186f9b0765edf0fc6d92c76604fda6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c08323becd878127866e234f0f30c417d0d95b67a0336602315ee26cf8b988dd"

  strings:
    $s1 = "function _BHo0(s) {var _WJi0 = new Date();_WJi0.setUTCFullYear(\"2003\");if (_WJi0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _BHo0(s) {var _WJi0 = new Date();_WJi0.setUTCFullYear(\"2003\");if (_WJi0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _QXc2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}