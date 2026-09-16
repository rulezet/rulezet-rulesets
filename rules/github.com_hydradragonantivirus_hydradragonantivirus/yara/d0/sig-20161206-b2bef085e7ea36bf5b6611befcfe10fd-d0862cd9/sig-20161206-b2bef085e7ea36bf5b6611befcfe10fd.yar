rule sig_20161206_b2bef085e7ea36bf5b6611befcfe10fd {
  meta:
    description = "datamaliciousorder - file 20161206_b2bef085e7ea36bf5b6611befcfe10fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ac1f8948d306a31728a4ab79a8f7b466479583e3703c1589f790598c9cb90f5"

  strings:
    $s1 = "var vVq5 = new Function(\"s\", '{var vXt8 = new Date();vXt8[\"setUTCFullYear\"](\"2003\");if (vXt8.getUTCFullYear().toString(10)" ascii
    $s2 = "var vVq5 = new Function(\"s\", '{var vXt8 = new Date();vXt8[\"setUTCFullYear\"](\"2003\");if (vXt8.getUTCFullYear().toString(10)" ascii
    $s3 = "function vXy3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vMZa6 = s.split(\"##\"); return vMZa6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}