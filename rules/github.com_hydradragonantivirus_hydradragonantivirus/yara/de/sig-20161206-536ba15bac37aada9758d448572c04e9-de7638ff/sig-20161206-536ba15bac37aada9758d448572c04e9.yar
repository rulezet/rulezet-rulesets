rule sig_20161206_536ba15bac37aada9758d448572c04e9 {
  meta:
    description = "datamaliciousorder - file 20161206_536ba15bac37aada9758d448572c04e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "334f010adfd0abe859d1fa8ca91493d7e690ae769eb143ab53622e1484246a7b"

  strings:
    $s1 = "function _Mf1(s) {var _Kc4 = new Date();_Kc4.setUTCFullYear(\"2003\");if (_Kc4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Mf1(s) {var _Kc4 = new Date();_Kc4.setUTCFullYear(\"2003\");if (_Kc4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Cw5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}