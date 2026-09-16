rule sig_20161205_0d3d770b9334e84eb15e1cea44cb18c7 {
  meta:
    description = "datamaliciousorder - file 20161205_0d3d770b9334e84eb15e1cea44cb18c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "708ea69888875238d58787f589d40d87971238d5de00183a5686787603705c90"

  strings:
    $s1 = "function _Pn6(s) {var _LJf3 = new Date();_LJf3.setUTCFullYear(\"2003\");if (_LJf3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Pn6(s) {var _LJf3 = new Date();_LJf3.setUTCFullYear(\"2003\");if (_LJf3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Pz8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}