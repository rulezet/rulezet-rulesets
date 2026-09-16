rule sig_20161206_c07d41967c5d0d63ff92986f7a1d1f05 {
  meta:
    description = "datamaliciousorder - file 20161206_c07d41967c5d0d63ff92986f7a1d1f05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0f6e205c5aacf2563e11d84a57aa8bd7d1e7265f02bcf5be3e852210d0da22e"

  strings:
    $s1 = "function _ANl4(s) {var _AHy4 = new Date();_AHy4.setUTCFullYear(\"2003\");if (_AHy4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _ANl4(s) {var _AHy4 = new Date();_AHy4.setUTCFullYear(\"2003\");if (_AHy4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _EBd3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}