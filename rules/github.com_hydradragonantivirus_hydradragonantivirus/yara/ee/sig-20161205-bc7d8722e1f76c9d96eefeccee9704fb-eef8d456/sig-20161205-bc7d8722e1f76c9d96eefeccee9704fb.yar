rule sig_20161205_bc7d8722e1f76c9d96eefeccee9704fb {
  meta:
    description = "datamaliciousorder - file 20161205_bc7d8722e1f76c9d96eefeccee9704fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d980f084dbf963873fdbe71215e31ec406b9726e423778eb820656ca1eaaf663"

  strings:
    $s1 = "function _FSo7(s) {var _MEc0 = new Date();_MEc0.setUTCFullYear(\"2003\");if (_MEc0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _FSo7(s) {var _MEc0 = new Date();_MEc0.setUTCFullYear(\"2003\");if (_MEc0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Dx0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}