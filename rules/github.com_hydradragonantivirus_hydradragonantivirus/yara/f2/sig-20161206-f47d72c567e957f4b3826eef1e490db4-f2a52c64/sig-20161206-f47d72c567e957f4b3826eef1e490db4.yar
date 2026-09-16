rule sig_20161206_f47d72c567e957f4b3826eef1e490db4 {
  meta:
    description = "datamaliciousorder - file 20161206_f47d72c567e957f4b3826eef1e490db4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e1738dd7dc209946200d1685b70c313c0a588ae45ab1b785ed4369994503c5f"

  strings:
    $s1 = "function _TXb1(s) {var _AYm2 = new Date();_AYm2.setUTCFullYear(\"2003\");if (_AYm2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _TXb1(s) {var _AYm2 = new Date();_AYm2.setUTCFullYear(\"2003\");if (_AYm2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Wn6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}