rule sig_20161205_32469d98d49c50ec9aa069271ff7da50 {
  meta:
    description = "datamaliciousorder - file 20161205_32469d98d49c50ec9aa069271ff7da50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c7ebcf0b3cdbb04c26693e92c32629479ba649b2862eda48b73e01f0114c82f"

  strings:
    $s1 = "function _Gz3(s) {var _GBg2 = new Date();_GBg2.setUTCFullYear(\"2003\");if (_GBg2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Gz3(s) {var _GBg2 = new Date();_GBg2.setUTCFullYear(\"2003\");if (_GBg2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Lj3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}