rule sig_20161205_6d4e5afade310cb202f40b9b181f3551 {
  meta:
    description = "datamaliciousorder - file 20161205_6d4e5afade310cb202f40b9b181f3551.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "168e018a71d452ea5e1fd6e4a826413e8253d218e277a603361effa1db143af0"

  strings:
    $s1 = "function _VLk5(s) {var _ZOk2 = new Date();_ZOk2.setUTCFullYear(\"2003\");if (_ZOk2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _VLk5(s) {var _ZOk2 = new Date();_ZOk2.setUTCFullYear(\"2003\");if (_ZOk2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _BYh4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}