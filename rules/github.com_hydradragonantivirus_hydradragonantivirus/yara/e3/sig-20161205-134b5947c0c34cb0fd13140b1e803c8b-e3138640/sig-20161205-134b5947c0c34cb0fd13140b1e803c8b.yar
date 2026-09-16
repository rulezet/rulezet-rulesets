rule sig_20161205_134b5947c0c34cb0fd13140b1e803c8b {
  meta:
    description = "datamaliciousorder - file 20161205_134b5947c0c34cb0fd13140b1e803c8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "813c0a45487927ca8390314d14befca380b5b917df0c963c57e186c4358b192c"

  strings:
    $s1 = "function _IGs0(s) {var _Eg2 = new Date();_Eg2.setUTCFullYear(\"2003\");if (_Eg2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _IGs0(s) {var _Eg2 = new Date();_Eg2.setUTCFullYear(\"2003\");if (_Eg2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _AFa0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}