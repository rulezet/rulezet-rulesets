rule sig_20161206_6186a248fe96a28d9f0f6f9712b6ff7f {
  meta:
    description = "datamaliciousorder - file 20161206_6186a248fe96a28d9f0f6f9712b6ff7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1eb9e6413c6d6df552962d1a7a44f6b1a1a39327c72b4ec192f6962c17706ce"

  strings:
    $s1 = "var vMj0 = new Function(\"s\", '{var vRp7 = new Date();vRp7[\"setUTCFullYear\"](\"2003\");if (vRp7.getUTCFullYear().toString(10)" ascii
    $s2 = "var vMj0 = new Function(\"s\", '{var vRp7 = new Date();vRp7[\"setUTCFullYear\"](\"2003\");if (vRp7.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vGBn8 = s.split(\"##\"); return vGBn8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vFd6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}