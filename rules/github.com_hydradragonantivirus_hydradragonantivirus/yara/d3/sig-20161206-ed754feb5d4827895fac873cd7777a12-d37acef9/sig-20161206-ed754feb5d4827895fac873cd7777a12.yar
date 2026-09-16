rule sig_20161206_ed754feb5d4827895fac873cd7777a12 {
  meta:
    description = "datamaliciousorder - file 20161206_ed754feb5d4827895fac873cd7777a12.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a280778a97149865ceec6acf6fe0d6f58e2b5d8c0c01b97bbb633ee809fd548c"

  strings:
    $s1 = "function _FNp4(s) {var _MVi6 = new Date();_MVi6.setUTCFullYear(\"2003\");if (_MVi6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _FNp4(s) {var _MVi6 = new Date();_MVi6.setUTCFullYear(\"2003\");if (_MVi6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Vg2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}