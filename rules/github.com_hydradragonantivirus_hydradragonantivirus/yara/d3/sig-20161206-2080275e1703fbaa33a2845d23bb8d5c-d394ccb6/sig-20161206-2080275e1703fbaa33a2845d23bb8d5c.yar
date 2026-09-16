rule sig_20161206_2080275e1703fbaa33a2845d23bb8d5c {
  meta:
    description = "datamaliciousorder - file 20161206_2080275e1703fbaa33a2845d23bb8d5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34b9d269a1edf1bce32f5d330103e84bc0c4622b12e68fb05ec9dbc880dd0cf1"

  strings:
    $s1 = "function _Px1(s) {var _Ib8 = new Date();_Ib8.setUTCFullYear(\"2003\");if (_Ib8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Px1(s) {var _Ib8 = new Date();_Ib8.setUTCFullYear(\"2003\");if (_Ib8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Bp0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}