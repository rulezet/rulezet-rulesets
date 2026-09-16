rule sig_20161205_dd7e62e12f8e4b3df482d31a99683c31 {
  meta:
    description = "datamaliciousorder - file 20161205_dd7e62e12f8e4b3df482d31a99683c31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88a145e62100023b6ce292b9bc6d88011754e4683c96946c08521d3788b9ee3e"

  strings:
    $s1 = "function _KZd0(s) {var _AKu5 = new Date();_AKu5.setUTCFullYear(\"2003\");if (_AKu5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _KZd0(s) {var _AKu5 = new Date();_AKu5.setUTCFullYear(\"2003\");if (_AKu5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Tw2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}