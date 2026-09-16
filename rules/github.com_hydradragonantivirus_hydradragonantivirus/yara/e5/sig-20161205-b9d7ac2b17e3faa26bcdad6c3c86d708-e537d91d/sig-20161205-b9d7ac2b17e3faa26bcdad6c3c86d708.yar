rule sig_20161205_b9d7ac2b17e3faa26bcdad6c3c86d708 {
  meta:
    description = "datamaliciousorder - file 20161205_b9d7ac2b17e3faa26bcdad6c3c86d708.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff46cf978b0716452b18851c26a3fba12714924447631cd58ccb5065d0d52abc"

  strings:
    $s1 = "function _Da4(s) {var _YUh6 = new Date();_YUh6.setUTCFullYear(\"2003\");if (_YUh6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Da4(s) {var _YUh6 = new Date();_YUh6.setUTCFullYear(\"2003\");if (_YUh6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _VMv5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}