rule sig_20161206_38b452ccdd3a7df8bdd76b751987c4e0 {
  meta:
    description = "datamaliciousorder - file 20161206_38b452ccdd3a7df8bdd76b751987c4e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd967bd3d3165376a94bdf81b994f54e17b269972c78dcf765cf363299c22f28"

  strings:
    $s1 = "var vXQm9 = new Function(\"s\", '{var vCGr9 = new Date();vCGr9[\"setUTCFullYear\"](\"2003\");if (vCGr9.getUTCFullYear().toString" ascii
    $s2 = "var vXQm9 = new Function(\"s\", '{var vCGr9 = new Date();vCGr9[\"setUTCFullYear\"](\"2003\");if (vCGr9.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vFSg4 = s.split(\"##\"); return vFSg4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vQa9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}