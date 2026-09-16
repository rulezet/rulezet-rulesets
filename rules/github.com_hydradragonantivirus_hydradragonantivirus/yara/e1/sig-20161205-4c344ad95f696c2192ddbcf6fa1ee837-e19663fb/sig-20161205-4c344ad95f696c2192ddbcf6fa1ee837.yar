rule sig_20161205_4c344ad95f696c2192ddbcf6fa1ee837 {
  meta:
    description = "datamaliciousorder - file 20161205_4c344ad95f696c2192ddbcf6fa1ee837.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8084869add6d8a9e4696aea106f301a70b3272a20752351271c276bfdf76a44e"

  strings:
    $s1 = "function _YSs6(s) {var _DOd7 = new Date();_DOd7.setUTCFullYear(\"2003\");if (_DOd7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _YSs6(s) {var _DOd7 = new Date();_DOd7.setUTCFullYear(\"2003\");if (_DOd7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _SAz4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}