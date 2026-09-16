rule sig_20161205_b96f3b022fb91ea4e392a64296a9fc11 {
  meta:
    description = "datamaliciousorder - file 20161205_b96f3b022fb91ea4e392a64296a9fc11.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "095d1f4e2d8e37ef96f0f0be880c05f84ebad2a3eacc11c53fa29595e2bfa6c5"

  strings:
    $s1 = "function _Ua5(s) {var _QMr6 = new Date();_QMr6.setUTCFullYear(\"2003\");if (_QMr6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ua5(s) {var _QMr6 = new Date();_QMr6.setUTCFullYear(\"2003\");if (_QMr6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Tv1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}