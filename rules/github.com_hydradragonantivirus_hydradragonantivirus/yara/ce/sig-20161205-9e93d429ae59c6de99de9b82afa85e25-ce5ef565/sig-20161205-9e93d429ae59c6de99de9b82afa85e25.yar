rule sig_20161205_9e93d429ae59c6de99de9b82afa85e25 {
  meta:
    description = "datamaliciousorder - file 20161205_9e93d429ae59c6de99de9b82afa85e25.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e501fd25c766520d1f14a739cf7a2c522330256eccfa5459f02b674d05ec426"

  strings:
    $s1 = "function _Hd9(s) {var _Eo5 = new Date();_Eo5.setUTCFullYear(\"2003\");if (_Eo5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Hd9(s) {var _Eo5 = new Date();_Eo5.setUTCFullYear(\"2003\");if (_Eo5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _NYf6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}