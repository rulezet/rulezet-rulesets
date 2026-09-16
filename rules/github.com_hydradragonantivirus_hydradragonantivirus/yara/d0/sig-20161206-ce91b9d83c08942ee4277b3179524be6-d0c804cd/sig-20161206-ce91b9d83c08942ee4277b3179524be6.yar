rule sig_20161206_ce91b9d83c08942ee4277b3179524be6 {
  meta:
    description = "datamaliciousorder - file 20161206_ce91b9d83c08942ee4277b3179524be6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c22ebd1f1b8ad4b25e96666bb1f64750cfc8554e60b684cdee4d4ec554742e38"

  strings:
    $s1 = "var vFb0 = new Function(\"s\", '{var vZd9 = new Date();vZd9[\"setUTCFullYear\"](\"2003\");if (vZd9.getUTCFullYear().toString(10)" ascii
    $s2 = "var vFb0 = new Function(\"s\", '{var vZd9 = new Date();vZd9[\"setUTCFullYear\"](\"2003\");if (vZd9.getUTCFullYear().toString(10)" ascii
    $s3 = "function vPXw4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vMj8 = s.split(\"##\"); return vMj8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}