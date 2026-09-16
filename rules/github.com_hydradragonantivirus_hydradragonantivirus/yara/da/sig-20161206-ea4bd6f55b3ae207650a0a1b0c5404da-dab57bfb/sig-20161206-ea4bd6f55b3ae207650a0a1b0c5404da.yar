rule sig_20161206_ea4bd6f55b3ae207650a0a1b0c5404da {
  meta:
    description = "datamaliciousorder - file 20161206_ea4bd6f55b3ae207650a0a1b0c5404da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c42f3945269da049cde3499ed9dbf3f10a2686fe4191722634afb21ab113b65"

  strings:
    $s1 = "var vYJk9 = new Function(\"s\", '{var vUr4 = new Date();vUr4[\"setUTCFullYear\"](\"2003\");if (vUr4.getUTCFullYear().toString(10" ascii
    $s2 = "var vYJk9 = new Function(\"s\", '{var vUr4 = new Date();vUr4[\"setUTCFullYear\"](\"2003\");if (vUr4.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vIVz7 = s.split(\"##\"); return vIVz7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vRy0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}