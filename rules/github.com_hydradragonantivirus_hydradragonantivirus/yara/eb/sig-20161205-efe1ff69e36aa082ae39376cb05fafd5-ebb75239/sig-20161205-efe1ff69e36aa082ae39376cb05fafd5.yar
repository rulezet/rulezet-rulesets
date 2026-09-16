rule sig_20161205_efe1ff69e36aa082ae39376cb05fafd5 {
  meta:
    description = "datamaliciousorder - file 20161205_efe1ff69e36aa082ae39376cb05fafd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f219d14dddc60358502f31e665b0796994da7b3d0fdff908829c984128783fb"

  strings:
    $s1 = "function _UUk7(s) {var _PBi3 = new Date();_PBi3.setUTCFullYear(\"2003\");if (_PBi3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _UUk7(s) {var _PBi3 = new Date();_PBi3.setUTCFullYear(\"2003\");if (_PBi3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Za9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}