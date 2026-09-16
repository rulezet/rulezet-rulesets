rule sig_20161206_bd11f02d843085ec88b4a23fdca83797 {
  meta:
    description = "datamaliciousorder - file 20161206_bd11f02d843085ec88b4a23fdca83797.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e194159f6a8d9e2f718dfdc5048adbb53c1d72c25ee139a034376e85cc335de"

  strings:
    $s1 = "function _Jg3(s) {var _XLl0 = new Date();_XLl0.setUTCFullYear(\"2003\");if (_XLl0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Jg3(s) {var _XLl0 = new Date();_XLl0.setUTCFullYear(\"2003\");if (_XLl0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _TNh9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}