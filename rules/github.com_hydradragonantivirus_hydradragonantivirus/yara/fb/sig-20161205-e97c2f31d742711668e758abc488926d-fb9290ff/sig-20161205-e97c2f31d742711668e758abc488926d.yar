rule sig_20161205_e97c2f31d742711668e758abc488926d {
  meta:
    description = "datamaliciousorder - file 20161205_e97c2f31d742711668e758abc488926d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3bd1c26e2f4381e95fffd4cecad9b90110366b918b2aa89419f6cc582d8331f"

  strings:
    $s1 = "function _Ho4(s) {var _LOk0 = new Date();_LOk0.setUTCFullYear(\"2003\");if (_LOk0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ho4(s) {var _LOk0 = new Date();_LOk0.setUTCFullYear(\"2003\");if (_LOk0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _GWt4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}