rule sig_20161205_dec3b3fcf14b3fa49cb877b00d135c67 {
  meta:
    description = "datamaliciousorder - file 20161205_dec3b3fcf14b3fa49cb877b00d135c67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1aa92e01f2a71aa4760953a1b50eac07939a011ce21b22d05c3b5ec3d897643"

  strings:
    $s1 = "function _Ff4(s) {var _NQk2 = new Date();_NQk2.setUTCFullYear(\"2003\");if (_NQk2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ff4(s) {var _NQk2 = new Date();_NQk2.setUTCFullYear(\"2003\");if (_NQk2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _SLx6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}