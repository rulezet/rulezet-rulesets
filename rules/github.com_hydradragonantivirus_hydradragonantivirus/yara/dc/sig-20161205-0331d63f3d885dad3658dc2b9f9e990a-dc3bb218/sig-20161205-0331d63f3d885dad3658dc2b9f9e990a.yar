rule sig_20161205_0331d63f3d885dad3658dc2b9f9e990a {
  meta:
    description = "datamaliciousorder - file 20161205_0331d63f3d885dad3658dc2b9f9e990a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f99a4e3f418732ba52c0cdeaee3d578eb5599d43a789c65f7fa72d51917bfb87"

  strings:
    $s1 = "function _Ye1(s) {var _GOt0 = new Date();_GOt0.setUTCFullYear(\"2003\");if (_GOt0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ye1(s) {var _GOt0 = new Date();_GOt0.setUTCFullYear(\"2003\");if (_GOt0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Uv3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}