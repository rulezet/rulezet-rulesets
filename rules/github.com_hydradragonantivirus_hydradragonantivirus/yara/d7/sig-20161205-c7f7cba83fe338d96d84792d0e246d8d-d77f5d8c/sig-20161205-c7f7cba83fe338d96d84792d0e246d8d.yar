rule sig_20161205_c7f7cba83fe338d96d84792d0e246d8d {
  meta:
    description = "datamaliciousorder - file 20161205_c7f7cba83fe338d96d84792d0e246d8d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b06d4f47cbe639379ba0042e9d1cd893004cf9f5043a20668ebb8bd1c686dc02"

  strings:
    $s1 = "function _OHw8(s) {var _YHp4 = new Date();_YHp4.setUTCFullYear(\"2003\");if (_YHp4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _OHw8(s) {var _YHp4 = new Date();_YHp4.setUTCFullYear(\"2003\");if (_YHp4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _XDz3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}