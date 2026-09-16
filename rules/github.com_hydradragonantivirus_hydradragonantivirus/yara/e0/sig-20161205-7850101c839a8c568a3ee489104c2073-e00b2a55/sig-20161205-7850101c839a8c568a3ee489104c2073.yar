rule sig_20161205_7850101c839a8c568a3ee489104c2073 {
  meta:
    description = "datamaliciousorder - file 20161205_7850101c839a8c568a3ee489104c2073.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0af03eebb7af450b48381218bb43ac1fb67198e3a01e7fffc8c89f48bbe807b"

  strings:
    $s1 = "function _Fh3(s) {var _DYu6 = new Date();_DYu6.setUTCFullYear(\"2003\");if (_DYu6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Fh3(s) {var _DYu6 = new Date();_DYu6.setUTCFullYear(\"2003\");if (_DYu6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _EVh9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}