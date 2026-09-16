rule sig_20161206_fcf5c22e4dcb1500fc317861520baeb0 {
  meta:
    description = "datamaliciousorder - file 20161206_fcf5c22e4dcb1500fc317861520baeb0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcd984f26a4bdb884367dcaf871eadc811b5dae16af9e495f7166af7dc23d77f"

  strings:
    $s1 = "function _Qs7(s) {var _UXn6 = new Date();_UXn6.setUTCFullYear(\"2003\");if (_UXn6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Qs7(s) {var _UXn6 = new Date();_UXn6.setUTCFullYear(\"2003\");if (_UXn6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _VAo2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}