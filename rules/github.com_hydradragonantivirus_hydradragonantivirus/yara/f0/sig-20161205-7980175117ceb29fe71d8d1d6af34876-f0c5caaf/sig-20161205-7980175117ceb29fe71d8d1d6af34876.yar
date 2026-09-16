rule sig_20161205_7980175117ceb29fe71d8d1d6af34876 {
  meta:
    description = "datamaliciousorder - file 20161205_7980175117ceb29fe71d8d1d6af34876.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eba2e8db8710ddc51776201e102c68cecd395c8f603fbb99fb0c4e223fe6f21b"

  strings:
    $s1 = "function _MKd0(s) {var _Da0 = new Date();_Da0.setUTCFullYear(\"2003\");if (_Da0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _MKd0(s) {var _Da0 = new Date();_Da0.setUTCFullYear(\"2003\");if (_Da0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _MKi0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}