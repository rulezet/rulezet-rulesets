rule sig_20161206_509848b95f835c1b6058e1cfc35f3ffb {
  meta:
    description = "datamaliciousorder - file 20161206_509848b95f835c1b6058e1cfc35f3ffb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4a1b102beb39b204f3cba4b6b62ae9d29fdc0ebaf52d4f1cc595d7fe66eb01c"

  strings:
    $s1 = "function _Ht9(s) {var _Rp3 = new Date();_Rp3.setUTCFullYear(\"2003\");if (_Rp3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ht9(s) {var _Rp3 = new Date();_Rp3.setUTCFullYear(\"2003\");if (_Rp3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _TKt5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}