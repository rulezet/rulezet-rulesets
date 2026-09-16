rule sig_20161205_fcbaf485edab9387910ea70c7757d391 {
  meta:
    description = "datamaliciousorder - file 20161205_fcbaf485edab9387910ea70c7757d391.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecb9aa7b971d03868f0f4726a4104a6723f14eb13235e7594f3068a2075fe080"

  strings:
    $s1 = "function _ZNi2(s) {var _OOu8 = new Date();_OOu8.setUTCFullYear(\"2003\");if (_OOu8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _ZNi2(s) {var _OOu8 = new Date();_OOu8.setUTCFullYear(\"2003\");if (_OOu8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _GJd9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}