rule sig_20161205_c5c3af301de959f843a596e126b7ef9d {
  meta:
    description = "datamaliciousorder - file 20161205_c5c3af301de959f843a596e126b7ef9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acb728b76ddb34f2892781703508b2d5b595afddd0833e7cd9fe74933475a39b"

  strings:
    $s1 = "function _IVr4(s) {var _QUk2 = new Date();_QUk2.setUTCFullYear(\"2003\");if (_QUk2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _IVr4(s) {var _QUk2 = new Date();_QUk2.setUTCFullYear(\"2003\");if (_QUk2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Tp6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}