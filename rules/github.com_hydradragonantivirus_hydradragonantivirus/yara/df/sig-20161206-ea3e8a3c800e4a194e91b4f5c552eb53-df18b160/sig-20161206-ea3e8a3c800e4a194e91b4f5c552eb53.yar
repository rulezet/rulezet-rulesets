rule sig_20161206_ea3e8a3c800e4a194e91b4f5c552eb53 {
  meta:
    description = "datamaliciousorder - file 20161206_ea3e8a3c800e4a194e91b4f5c552eb53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40262ad442fab6da483d77aeaf588036be250f113b8a14a8ff3953472b06b386"

  strings:
    $s1 = "function _Hs6(s) {var _CIt4 = new Date();_CIt4.setUTCFullYear(\"2003\");if (_CIt4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Hs6(s) {var _CIt4 = new Date();_CIt4.setUTCFullYear(\"2003\");if (_CIt4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Dp0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}