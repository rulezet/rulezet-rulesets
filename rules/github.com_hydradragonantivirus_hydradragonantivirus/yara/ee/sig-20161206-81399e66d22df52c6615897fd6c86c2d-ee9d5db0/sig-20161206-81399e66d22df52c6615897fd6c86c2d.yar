rule sig_20161206_81399e66d22df52c6615897fd6c86c2d {
  meta:
    description = "datamaliciousorder - file 20161206_81399e66d22df52c6615897fd6c86c2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e5ac4157aa9a1961c81a26c16aedb53232ef71bc1f7d3b08cfc23c835b38c53"

  strings:
    $s1 = "function _JHh2(s) {var _Up7 = new Date();_Up7.setUTCFullYear(\"2003\");if (_Up7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _JHh2(s) {var _Up7 = new Date();_Up7.setUTCFullYear(\"2003\");if (_Up7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _RQz8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}