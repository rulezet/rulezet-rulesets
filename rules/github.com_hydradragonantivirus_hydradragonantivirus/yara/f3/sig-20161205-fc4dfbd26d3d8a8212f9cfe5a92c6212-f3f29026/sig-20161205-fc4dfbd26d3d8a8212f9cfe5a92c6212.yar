rule sig_20161205_fc4dfbd26d3d8a8212f9cfe5a92c6212 {
  meta:
    description = "datamaliciousorder - file 20161205_fc4dfbd26d3d8a8212f9cfe5a92c6212.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f0f6f733217b1054c8913c228cdd4f76bb4491ef220b4143b004430fc4b85c9"

  strings:
    $s1 = "function _YTw9(s) {var _RUj6 = new Date();_RUj6.setUTCFullYear(\"2003\");if (_RUj6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _YTw9(s) {var _RUj6 = new Date();_RUj6.setUTCFullYear(\"2003\");if (_RUj6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Pz6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}