rule sig_20161206_a101a57b52a9023273d5cfeea4db7671 {
  meta:
    description = "datamaliciousorder - file 20161206_a101a57b52a9023273d5cfeea4db7671.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8276511e3e774412ec7360d3ea0c2f53347d2b4f539f06020a29f565e8b20bc2"

  strings:
    $s1 = "function _Cl4(s) {var _MHg5 = new Date();_MHg5.setUTCFullYear(\"2003\");if (_MHg5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Cl4(s) {var _MHg5 = new Date();_MHg5.setUTCFullYear(\"2003\");if (_MHg5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Yh5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}