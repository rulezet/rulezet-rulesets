rule sig_20161207_f875ab8c6b926728b0b1f1b25908456f {
  meta:
    description = "datamaliciousorder - file 20161207_f875ab8c6b926728b0b1f1b25908456f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07b9bc69d38cec3e960cbeea3703fd7be50a5a0507d3304ea304e3cb342e6701"

  strings:
    $s1 = "var vYr7 = new Function(\"vQSf3\", '{var vYw1 = new Date();vYw1[\"setUTCFullYear\"](\"2003\");if (vYw1.getUTCFullYear().toString" ascii
    $s2 = "var vYr7 = new Function(\"vQSf3\", '{var vYw1 = new Date();vYw1[\"setUTCFullYear\"](\"2003\");if (vYw1.getUTCFullYear().toString" ascii
    $s3 = "var vDOm0 = new Function(\"vQSf3\", '{return vQSf3.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vBj5 = vQSf3.split(\"###\"); return vBj5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}