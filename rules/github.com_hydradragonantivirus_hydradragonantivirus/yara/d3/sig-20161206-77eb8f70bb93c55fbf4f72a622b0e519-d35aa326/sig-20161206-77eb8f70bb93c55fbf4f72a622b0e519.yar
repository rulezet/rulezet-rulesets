rule sig_20161206_77eb8f70bb93c55fbf4f72a622b0e519 {
  meta:
    description = "datamaliciousorder - file 20161206_77eb8f70bb93c55fbf4f72a622b0e519.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4b7c7e5872e5168d128091375734429110983b4ffe481a8ebbb4e31c21c3bdb"

  strings:
    $s1 = "function _Bq0(s) {var _Dh8 = new Date();_Dh8.setUTCFullYear(\"2003\");if (_Dh8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Bq0(s) {var _Dh8 = new Date();_Dh8.setUTCFullYear(\"2003\");if (_Dh8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Xv3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}