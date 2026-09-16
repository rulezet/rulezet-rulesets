rule sig_20161205_ca9099d6ef7446278031c4cb38ac3714 {
  meta:
    description = "datamaliciousorder - file 20161205_ca9099d6ef7446278031c4cb38ac3714.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c288cf4079a69f6583ea942da46f869f752b01ebd49ad8377ab39071b0064f8"

  strings:
    $s1 = "function _Hn5(s) {var _JXn1 = new Date();_JXn1.setUTCFullYear(\"2003\");if (_JXn1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Hn5(s) {var _JXn1 = new Date();_JXn1.setUTCFullYear(\"2003\");if (_JXn1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _ZZh4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}