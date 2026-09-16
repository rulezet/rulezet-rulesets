rule sig_20161205_edaab7fc1818996d1124238c33fbc55a {
  meta:
    description = "datamaliciousorder - file 20161205_edaab7fc1818996d1124238c33fbc55a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a90f1be570611843f70254ae1a7dadb63921a13bd960f8ec7f9e02b7de267d18"

  strings:
    $s1 = "function _HPh3(s) {var _NNd0 = new Date();_NNd0.setUTCFullYear(\"2003\");if (_NNd0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _HPh3(s) {var _NNd0 = new Date();_NNd0.setUTCFullYear(\"2003\");if (_NNd0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Yg8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}