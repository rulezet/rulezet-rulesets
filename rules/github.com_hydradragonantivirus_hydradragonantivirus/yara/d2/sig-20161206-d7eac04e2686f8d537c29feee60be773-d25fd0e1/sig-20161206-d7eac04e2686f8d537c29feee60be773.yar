rule sig_20161206_d7eac04e2686f8d537c29feee60be773 {
  meta:
    description = "datamaliciousorder - file 20161206_d7eac04e2686f8d537c29feee60be773.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06b1fad1950b99d9faefd0d1fce01fffa5e602f6146f2a6e8b2ec4d0b0e979f0"

  strings:
    $s1 = "var vFy9 = new Function(\"s\", '{var vOl0 = new Date();vOl0[\"setUTCFullYear\"](\"2003\");if (vOl0.getUTCFullYear().toString(10)" ascii
    $s2 = "var vFy9 = new Function(\"s\", '{var vOl0 = new Date();vOl0[\"setUTCFullYear\"](\"2003\");if (vOl0.getUTCFullYear().toString(10)" ascii
    $s3 = "function vQn3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vUk5 = s.split(\"##\"); return vUk5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}