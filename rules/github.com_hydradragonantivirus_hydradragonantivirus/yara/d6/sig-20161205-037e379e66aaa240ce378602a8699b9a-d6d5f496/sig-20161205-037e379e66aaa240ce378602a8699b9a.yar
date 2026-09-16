rule sig_20161205_037e379e66aaa240ce378602a8699b9a {
  meta:
    description = "datamaliciousorder - file 20161205_037e379e66aaa240ce378602a8699b9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2035733cf0fd94e7ef061777807ef88d79cdddc688c3d26b2eec5da00413b671"

  strings:
    $s1 = "function _Xh6(s) {var _RWh8 = new Date();_RWh8.setUTCFullYear(\"2003\");if (_RWh8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Xh6(s) {var _RWh8 = new Date();_RWh8.setUTCFullYear(\"2003\");if (_RWh8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _ERv8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}