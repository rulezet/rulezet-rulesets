rule sig_20161206_1f41817fc8797769b15c0e6b52cd3f67 {
  meta:
    description = "datamaliciousorder - file 20161206_1f41817fc8797769b15c0e6b52cd3f67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6215f4917aadbfce9da10f2ab1e4694738382ad5fd5adad8ccd0744b1c53530"

  strings:
    $s1 = "function _UId6(s) {var _LZq7 = new Date();_LZq7.setUTCFullYear(\"2003\");if (_LZq7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _UId6(s) {var _LZq7 = new Date();_LZq7.setUTCFullYear(\"2003\");if (_LZq7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Id4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}