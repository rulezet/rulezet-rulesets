rule sig_20161206_a6a070629b5abb37cd7ee8154ab9e02f {
  meta:
    description = "datamaliciousorder - file 20161206_a6a070629b5abb37cd7ee8154ab9e02f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99d2bfcaa116d6132f02a356f2f1b3cfa373b049fd835bf6fdc196d99bb1534f"

  strings:
    $s1 = "function _URr9(s) {var _ZBy4 = new Date();_ZBy4.setUTCFullYear(\"2003\");if (_ZBy4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _URr9(s) {var _ZBy4 = new Date();_ZBy4.setUTCFullYear(\"2003\");if (_ZBy4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _EOe5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}