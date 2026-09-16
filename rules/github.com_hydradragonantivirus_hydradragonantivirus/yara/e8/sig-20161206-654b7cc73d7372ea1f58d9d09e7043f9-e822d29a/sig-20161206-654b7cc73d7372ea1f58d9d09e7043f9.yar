rule sig_20161206_654b7cc73d7372ea1f58d9d09e7043f9 {
  meta:
    description = "datamaliciousorder - file 20161206_654b7cc73d7372ea1f58d9d09e7043f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0e3f3c76bf09bdfc8600b9656b3dd2a750a582ab3fdc3cac6d920e27e89ad1c"

  strings:
    $s1 = "function _OYg6(s) {var _Sr4 = new Date();_Sr4.setUTCFullYear(\"2003\");if (_Sr4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _OYg6(s) {var _Sr4 = new Date();_Sr4.setUTCFullYear(\"2003\");if (_Sr4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _ITb9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}