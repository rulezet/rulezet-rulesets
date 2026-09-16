rule sig_20161205_a1bb42a270046b44616166df8c97f8e6 {
  meta:
    description = "datamaliciousorder - file 20161205_a1bb42a270046b44616166df8c97f8e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c3e0d595459e462f74d2cb6eeb2ca2a7c85dc7eab631775679558dd6db3bd09"

  strings:
    $s1 = "function _KNu4(s) {var _TEv5 = new Date();_TEv5.setUTCFullYear(\"2003\");if (_TEv5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _KNu4(s) {var _TEv5 = new Date();_TEv5.setUTCFullYear(\"2003\");if (_TEv5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _VVd3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}