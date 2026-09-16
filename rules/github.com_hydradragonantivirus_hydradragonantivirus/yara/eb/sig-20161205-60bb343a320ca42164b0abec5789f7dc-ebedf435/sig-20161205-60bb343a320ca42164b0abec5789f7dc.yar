rule sig_20161205_60bb343a320ca42164b0abec5789f7dc {
  meta:
    description = "datamaliciousorder - file 20161205_60bb343a320ca42164b0abec5789f7dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75e4f4aeb13daf53c4d5bf2db964da53a8688e7282ab20b1c59433a863bf86eb"

  strings:
    $s1 = "function _KKq8(s) {var _Oy5 = new Date();_Oy5.setUTCFullYear(\"2003\");if (_Oy5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _KKq8(s) {var _Oy5 = new Date();_Oy5.setUTCFullYear(\"2003\");if (_Oy5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _FAj7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}