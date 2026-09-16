rule sig_20161205_7d52a9c916f4636b55799066879e8849 {
  meta:
    description = "datamaliciousorder - file 20161205_7d52a9c916f4636b55799066879e8849.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "347e54457c080d69b1082fb9c9b920c8e27694bd85d72a90002ffa97e4c1c7b9"

  strings:
    $s1 = "function _Rk9(s) {var _XXa7 = new Date();_XXa7.setUTCFullYear(\"2003\");if (_XXa7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Rk9(s) {var _XXa7 = new Date();_XXa7.setUTCFullYear(\"2003\");if (_XXa7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _ZHw6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}