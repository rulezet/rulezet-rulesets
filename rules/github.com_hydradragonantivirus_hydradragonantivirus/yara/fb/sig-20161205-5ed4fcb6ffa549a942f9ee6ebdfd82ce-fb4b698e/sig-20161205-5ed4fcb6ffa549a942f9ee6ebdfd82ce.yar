rule sig_20161205_5ed4fcb6ffa549a942f9ee6ebdfd82ce {
  meta:
    description = "datamaliciousorder - file 20161205_5ed4fcb6ffa549a942f9ee6ebdfd82ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88e6db3c12c691948a26bce552cbd26576c50a16761b0b6af13de176b9746af7"

  strings:
    $s1 = "function _Jz4(s) {var _SMo7 = new Date();_SMo7.setUTCFullYear(\"2003\");if (_SMo7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Jz4(s) {var _SMo7 = new Date();_SMo7.setUTCFullYear(\"2003\");if (_SMo7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Bb5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}