rule sig_20161205_5674eb750b496c67e16db003a2c25e7e {
  meta:
    description = "datamaliciousorder - file 20161205_5674eb750b496c67e16db003a2c25e7e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7e6df9831b7c48dbbf7097cd5f9252419d1d0808d66868982f362da20c37ea0"

  strings:
    $s1 = "function _PLf8(s) {var _Kx4 = new Date();_Kx4.setUTCFullYear(\"2003\");if (_Kx4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _PLf8(s) {var _Kx4 = new Date();_Kx4.setUTCFullYear(\"2003\");if (_Kx4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _MGo0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}