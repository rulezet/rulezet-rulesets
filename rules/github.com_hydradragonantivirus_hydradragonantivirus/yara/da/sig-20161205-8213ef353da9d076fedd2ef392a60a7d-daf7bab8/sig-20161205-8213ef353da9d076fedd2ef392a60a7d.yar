rule sig_20161205_8213ef353da9d076fedd2ef392a60a7d {
  meta:
    description = "datamaliciousorder - file 20161205_8213ef353da9d076fedd2ef392a60a7d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55cba6d25c6ee9fd2362e7123255c7451b4cc1a486e1fb242077afab16de7075"

  strings:
    $s1 = "function _SMn2(s) {var _PMi8 = new Date();_PMi8.setUTCFullYear(\"2003\");if (_PMi8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _SMn2(s) {var _PMi8 = new Date();_PMi8.setUTCFullYear(\"2003\");if (_PMi8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _VGk2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}