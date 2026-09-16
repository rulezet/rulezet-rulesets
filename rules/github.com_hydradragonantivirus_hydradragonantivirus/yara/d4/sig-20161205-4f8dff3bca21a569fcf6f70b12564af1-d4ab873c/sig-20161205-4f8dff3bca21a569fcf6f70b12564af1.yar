rule sig_20161205_4f8dff3bca21a569fcf6f70b12564af1 {
  meta:
    description = "datamaliciousorder - file 20161205_4f8dff3bca21a569fcf6f70b12564af1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29c4512f77a389ab642852296e60a002f3670482039fd317bb3671710d6209e3"

  strings:
    $s1 = "function _Uz3(s) {var _DWa6 = new Date();_DWa6.setUTCFullYear(\"2003\");if (_DWa6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Uz3(s) {var _DWa6 = new Date();_DWa6.setUTCFullYear(\"2003\");if (_DWa6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ho1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}