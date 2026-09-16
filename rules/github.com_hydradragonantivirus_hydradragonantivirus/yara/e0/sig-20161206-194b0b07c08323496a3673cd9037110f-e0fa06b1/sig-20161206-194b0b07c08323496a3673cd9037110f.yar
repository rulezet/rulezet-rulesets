rule sig_20161206_194b0b07c08323496a3673cd9037110f {
  meta:
    description = "datamaliciousorder - file 20161206_194b0b07c08323496a3673cd9037110f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20bccd7d0169db0c33e84fcbb0f41dea3a1fa5b2a8bcce42d69c93352a254e62"

  strings:
    $s1 = "function _Si1(s) {var _MRj9 = new Date();_MRj9.setUTCFullYear(\"2003\");if (_MRj9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Si1(s) {var _MRj9 = new Date();_MRj9.setUTCFullYear(\"2003\");if (_MRj9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ea2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}