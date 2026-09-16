rule sig_20161207_e1ec898f8800b85326a6301430828960 {
  meta:
    description = "datamaliciousorder - file 20161207_e1ec898f8800b85326a6301430828960.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d24ee7722e285ff97a03ab81b89090ecf2f739357e799418612963fa8160a8a4"

  strings:
    $s1 = "var vITb9 = new Function(\"vQBc3\", '{var vNXw3 = new Date();vNXw3[\"setUTCFullYear\"](\"2003\");if (vNXw3.getUTCFullYear().toSt" ascii
    $s2 = "var vITb9 = new Function(\"vQBc3\", '{var vNXw3 = new Date();vNXw3[\"setUTCFullYear\"](\"2003\");if (vNXw3.getUTCFullYear().toSt" ascii
    $s3 = "var vXMh7 = new Function(\"vQBc3\", '{return vQBc3.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "0) == \"2003\") {var vZNr7 = vQBc3.split(\"###\"); return vZNr7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}