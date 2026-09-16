rule sig_20161206_9b8b0e8699f16c4df885231412225099 {
  meta:
    description = "datamaliciousorder - file 20161206_9b8b0e8699f16c4df885231412225099.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6aa2b45ab6ec1ff74fccf455cd07203d04984ca6594ec764271c9825a112a140"

  strings:
    $s1 = "function _Us7(s) {var _Av5 = new Date();_Av5.setUTCFullYear(\"2003\");if (_Av5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Us7(s) {var _Av5 = new Date();_Av5.setUTCFullYear(\"2003\");if (_Av5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Sw1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}