rule sig_20161206_6154321de0e9b9e2376eeee0ab48cc91 {
  meta:
    description = "datamaliciousorder - file 20161206_6154321de0e9b9e2376eeee0ab48cc91.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8006d18fcd09eb19381bf2cb89ed9fed9141bc85e317cfa1b4adc28b80017f5d"

  strings:
    $s1 = "function _Fd0(s) {var _Jt0 = new Date();_Jt0.setUTCFullYear(\"2003\");if (_Jt0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Fd0(s) {var _Jt0 = new Date();_Jt0.setUTCFullYear(\"2003\");if (_Jt0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _MMs0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}