rule sig_20161206_4fc5ca84bf88527ec2f746fcfa1022e4 {
  meta:
    description = "datamaliciousorder - file 20161206_4fc5ca84bf88527ec2f746fcfa1022e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3aa077aaee1d84d68ecf6b422f923655b5135b5e05c81caef4d1072a0310b29f"

  strings:
    $s1 = "function _Kb0(s) {var _Uh9 = new Date();_Uh9.setUTCFullYear(\"2003\");if (_Uh9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Kb0(s) {var _Uh9 = new Date();_Uh9.setUTCFullYear(\"2003\");if (_Uh9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Dv6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}