rule sig_20161205_402514ce9ecb34840c50a9c5fd558883 {
  meta:
    description = "datamaliciousorder - file 20161205_402514ce9ecb34840c50a9c5fd558883.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "effa5acc7c5ebfdf6ea973ead7ddb804b6d67227ab0529d57a371d30e091db9e"

  strings:
    $s1 = "function _Tn6(s) {var _GEv2 = new Date();_GEv2.setUTCFullYear(\"2003\");if (_GEv2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Tn6(s) {var _GEv2 = new Date();_GEv2.setUTCFullYear(\"2003\");if (_GEv2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _TWs3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}