rule sig_20161206_d76997f3cf73f9fc707524c89df41bfe {
  meta:
    description = "datamaliciousorder - file 20161206_d76997f3cf73f9fc707524c89df41bfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "952a968e9a4323fcee654238963021081bde4e35dd6c181ced2ddc540c2e489b"

  strings:
    $s1 = "function _Vi8(s) {var _AAj3 = new Date();_AAj3.setUTCFullYear(\"2003\");if (_AAj3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Vi8(s) {var _AAj3 = new Date();_AAj3.setUTCFullYear(\"2003\");if (_AAj3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ra3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}