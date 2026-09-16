rule sig_20161205_6c26f1be3b39c2ded5be5d836aa9e6f6 {
  meta:
    description = "datamaliciousorder - file 20161205_6c26f1be3b39c2ded5be5d836aa9e6f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f6934996f4b9865058a33b765d2dc89b1b716031345186e5edf38fd9c1daf13"

  strings:
    $s1 = "function _JJy9(s) {var _Dm4 = new Date();_Dm4.setUTCFullYear(\"2003\");if (_Dm4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _JJy9(s) {var _Dm4 = new Date();_Dm4.setUTCFullYear(\"2003\");if (_Dm4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Ux5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}