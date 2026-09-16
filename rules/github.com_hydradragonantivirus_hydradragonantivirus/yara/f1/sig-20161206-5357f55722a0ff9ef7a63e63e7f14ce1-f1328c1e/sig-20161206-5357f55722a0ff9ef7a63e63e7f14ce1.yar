rule sig_20161206_5357f55722a0ff9ef7a63e63e7f14ce1 {
  meta:
    description = "datamaliciousorder - file 20161206_5357f55722a0ff9ef7a63e63e7f14ce1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da73fcd8a4e8d4a36f151898c613f3f540b62c5747d4fd0e9fba00c2c60d272a"

  strings:
    $s1 = "var vAs5 = new Function(\"s\", '{var vNz0 = new Date();vNz0[\"setUTCFullYear\"](\"2003\");if (vNz0.getUTCFullYear().toString(10)" ascii
    $s2 = "var vAs5 = new Function(\"s\", '{var vNz0 = new Date();vNz0[\"setUTCFullYear\"](\"2003\");if (vNz0.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vFb6 = s.split(\"##\"); return vFb6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vSDz3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}