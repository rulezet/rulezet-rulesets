rule sig_20161205_4612276dd754c548b02b1df3c245c432 {
  meta:
    description = "datamaliciousorder - file 20161205_4612276dd754c548b02b1df3c245c432.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed78070ac17b2109cfd88aea566acf6df9ed79aee57bc8332f1f8fab3c57028e"

  strings:
    $s1 = "function _MYr7(s) {var _JIy1 = new Date();_JIy1.setUTCFullYear(\"2003\");if (_JIy1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _MYr7(s) {var _JIy1 = new Date();_JIy1.setUTCFullYear(\"2003\");if (_JIy1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _EOm6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}