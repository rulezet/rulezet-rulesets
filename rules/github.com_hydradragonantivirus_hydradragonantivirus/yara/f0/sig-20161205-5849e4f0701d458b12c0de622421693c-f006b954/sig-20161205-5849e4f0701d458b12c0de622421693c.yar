rule sig_20161205_5849e4f0701d458b12c0de622421693c {
  meta:
    description = "datamaliciousorder - file 20161205_5849e4f0701d458b12c0de622421693c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e2c8f1c0b9f592d74adbd4acf7b5c4c72eff05df788f7ec2e6757e96a88fa3d"

  strings:
    $s1 = "function _BYn4(s) {var _MQf5 = new Date();_MQf5.setUTCFullYear(\"2003\");if (_MQf5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _BYn4(s) {var _MQf5 = new Date();_MQf5.setUTCFullYear(\"2003\");if (_MQf5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Jk1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}