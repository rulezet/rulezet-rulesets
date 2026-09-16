rule sig_20161206_370beb2010ed361d550c1e9418ef2f54 {
  meta:
    description = "datamaliciousorder - file 20161206_370beb2010ed361d550c1e9418ef2f54.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97a7c789b9c0ba09bf9e1cca12227897b988cafddb8b7601ff585cb0e5582893"

  strings:
    $s1 = "function _QDp2(s) {var _CNz0 = new Date();_CNz0.setUTCFullYear(\"2003\");if (_CNz0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _QDp2(s) {var _CNz0 = new Date();_CNz0.setUTCFullYear(\"2003\");if (_CNz0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Di4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}