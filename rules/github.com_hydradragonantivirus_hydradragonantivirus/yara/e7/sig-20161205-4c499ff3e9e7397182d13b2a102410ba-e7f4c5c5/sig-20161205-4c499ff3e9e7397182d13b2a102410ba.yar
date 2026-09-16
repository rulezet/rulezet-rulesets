rule sig_20161205_4c499ff3e9e7397182d13b2a102410ba {
  meta:
    description = "datamaliciousorder - file 20161205_4c499ff3e9e7397182d13b2a102410ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f22a265a068e4a6479efcccfa2eb7eb97dd9f062c7b4a689a6cf268158fc229"

  strings:
    $s1 = "function _XSs5(s) {var _Pd4 = new Date();_Pd4.setUTCFullYear(\"2003\");if (_Pd4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _XSs5(s) {var _Pd4 = new Date();_Pd4.setUTCFullYear(\"2003\");if (_Pd4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Zw0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}