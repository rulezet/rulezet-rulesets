rule sig_20161205_e797e031494c5e60bbd5aa328b837ba0 {
  meta:
    description = "datamaliciousorder - file 20161205_e797e031494c5e60bbd5aa328b837ba0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "421b2027cb7a9cc7f9539ffe8533bd6b664e5e608940dc0daf20a416d8278208"

  strings:
    $s1 = "function _SBj0(s) {var _IRy8 = new Date();_IRy8.setUTCFullYear(\"2003\");if (_IRy8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _SBj0(s) {var _IRy8 = new Date();_IRy8.setUTCFullYear(\"2003\");if (_IRy8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _TDn4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}