rule sig_20161207_a8a6510d18efc94fc1e4a2b5fd137d73 {
  meta:
    description = "datamaliciousorder - file 20161207_a8a6510d18efc94fc1e4a2b5fd137d73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2867dcc3ae7f689ead3c2eea612ab82cacd59372bd2f98cd10566b42aae0240"

  strings:
    $s1 = "var vHTs6 = new Function(\"vEp8\", '{var vSBj1 = new Date();vSBj1[\"setUTCFullYear\"](\"2003\");if (vSBj1.getUTCFullYear().toStr" ascii
    $s2 = "var vHTs6 = new Function(\"vEp8\", '{var vSBj1 = new Date();vSBj1[\"setUTCFullYear\"](\"2003\");if (vSBj1.getUTCFullYear().toStr" ascii
    $s3 = "var vSv5 = new Function(\"vEp8\", '{return vEp8.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vGWf7 = vEp8.split(\"###\"); return vGWf7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}