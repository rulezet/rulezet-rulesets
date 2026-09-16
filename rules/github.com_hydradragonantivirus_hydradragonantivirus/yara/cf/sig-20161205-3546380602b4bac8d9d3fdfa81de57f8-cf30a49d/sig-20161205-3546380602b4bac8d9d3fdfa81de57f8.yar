rule sig_20161205_3546380602b4bac8d9d3fdfa81de57f8 {
  meta:
    description = "datamaliciousorder - file 20161205_3546380602b4bac8d9d3fdfa81de57f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "684c79f0411b48aea1e2bd52a85fe8d084b32ac8db4924474b0eb15d726709e0"

  strings:
    $s1 = "function _Ar1(s) {var _RLx9 = new Date();_RLx9.setUTCFullYear(\"2003\");if (_RLx9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ar1(s) {var _RLx9 = new Date();_RLx9.setUTCFullYear(\"2003\");if (_RLx9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _AMz3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}