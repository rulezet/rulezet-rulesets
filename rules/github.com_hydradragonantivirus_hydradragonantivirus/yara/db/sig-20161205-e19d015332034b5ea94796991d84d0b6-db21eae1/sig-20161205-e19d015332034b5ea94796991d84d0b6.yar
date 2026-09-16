rule sig_20161205_e19d015332034b5ea94796991d84d0b6 {
  meta:
    description = "datamaliciousorder - file 20161205_e19d015332034b5ea94796991d84d0b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c94b16a84181e26180e5c7995bdc5f90bba7730f4f4842c6af6fbec8c8cc20a5"

  strings:
    $s1 = "function _Nr1(s) {var _ZLc0 = new Date();_ZLc0.setUTCFullYear(\"2003\");if (_ZLc0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Nr1(s) {var _ZLc0 = new Date();_ZLc0.setUTCFullYear(\"2003\");if (_ZLc0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Rb5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}