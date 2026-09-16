rule sig_20161206_e866018b5880176595db16c7ccd91c63 {
  meta:
    description = "datamaliciousorder - file 20161206_e866018b5880176595db16c7ccd91c63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e94509e740e6714574aee605f9c9e7b4e8a5cbdcc5c4ce6a4df68f1eed59a14"

  strings:
    $s1 = "function _Ll3(s) {var _NWi9 = new Date();_NWi9.setUTCFullYear(\"2003\");if (_NWi9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ll3(s) {var _NWi9 = new Date();_NWi9.setUTCFullYear(\"2003\");if (_NWi9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ql0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}