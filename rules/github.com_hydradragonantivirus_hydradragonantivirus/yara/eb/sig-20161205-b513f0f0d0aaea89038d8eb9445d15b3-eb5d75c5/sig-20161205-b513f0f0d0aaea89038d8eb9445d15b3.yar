rule sig_20161205_b513f0f0d0aaea89038d8eb9445d15b3 {
  meta:
    description = "datamaliciousorder - file 20161205_b513f0f0d0aaea89038d8eb9445d15b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e9588ae6f0ae4082b050e0880cb5a9b706a47c4d2ef6b660f9f897403486634"

  strings:
    $s1 = "function _Ju5(s) {var _Ld2 = new Date();_Ld2.setUTCFullYear(\"2003\");if (_Ld2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ju5(s) {var _Ld2 = new Date();_Ld2.setUTCFullYear(\"2003\");if (_Ld2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Fc9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}