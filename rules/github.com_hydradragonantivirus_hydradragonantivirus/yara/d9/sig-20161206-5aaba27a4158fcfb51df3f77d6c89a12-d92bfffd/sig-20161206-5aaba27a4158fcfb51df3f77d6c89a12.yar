rule sig_20161206_5aaba27a4158fcfb51df3f77d6c89a12 {
  meta:
    description = "datamaliciousorder - file 20161206_5aaba27a4158fcfb51df3f77d6c89a12.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6afe60845fd88c072b95947fab9c735f355e0ab725ee46d25280ff3b543d73c2"

  strings:
    $s1 = "var vEh5 = new Function(\"s\", '{var vNy6 = new Date();vNy6[\"setUTCFullYear\"](\"2003\");if (vNy6.getUTCFullYear().toString(10)" ascii
    $s2 = "var vEh5 = new Function(\"s\", '{var vNy6 = new Date();vNy6[\"setUTCFullYear\"](\"2003\");if (vNy6.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vZCl3 = s.split(\"##\"); return vZCl3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vLUg0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}