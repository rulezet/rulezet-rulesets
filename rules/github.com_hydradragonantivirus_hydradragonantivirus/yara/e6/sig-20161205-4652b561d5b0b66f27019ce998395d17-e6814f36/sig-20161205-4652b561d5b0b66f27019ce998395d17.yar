rule sig_20161205_4652b561d5b0b66f27019ce998395d17 {
  meta:
    description = "datamaliciousorder - file 20161205_4652b561d5b0b66f27019ce998395d17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26a075cf0b22d640e1037e48397910e6291269a5939952d8ccdbb723ee361332"

  strings:
    $s1 = "function _Py9(s) {var _NCt4 = new Date();_NCt4.setUTCFullYear(\"2003\");if (_NCt4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Py9(s) {var _NCt4 = new Date();_NCt4.setUTCFullYear(\"2003\");if (_NCt4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ui8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}