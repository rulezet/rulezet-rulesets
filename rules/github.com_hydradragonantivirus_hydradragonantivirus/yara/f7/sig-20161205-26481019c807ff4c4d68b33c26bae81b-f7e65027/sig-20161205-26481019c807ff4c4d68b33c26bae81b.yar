rule sig_20161205_26481019c807ff4c4d68b33c26bae81b {
  meta:
    description = "datamaliciousorder - file 20161205_26481019c807ff4c4d68b33c26bae81b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82a156e577ba50b218781cd317653a124cb43669ec55b658a01c2ebe335199c8"

  strings:
    $s1 = "function _IEl9(s) {var _FEj9 = new Date();_FEj9.setUTCFullYear(\"2003\");if (_FEj9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _IEl9(s) {var _FEj9 = new Date();_FEj9.setUTCFullYear(\"2003\");if (_FEj9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Wu0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}