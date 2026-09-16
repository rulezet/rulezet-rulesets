rule sig_20161207_7978d5b9b5dc33971c5e1c674e010ff3 {
  meta:
    description = "datamaliciousorder - file 20161207_7978d5b9b5dc33971c5e1c674e010ff3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ff6b57bc0d979ca8ef8a1846914a49c02a7327dbf7f0c4b54e4e96b18fa7a5d"

  strings:
    $s1 = "var vUBz0 = new Function(\"vOn6\", '{var vVAb5 = new Date();vVAb5[\"setUTCFullYear\"](\"2003\");if (vVAb5.getUTCFullYear().toStr" ascii
    $s2 = "var vUBz0 = new Function(\"vOn6\", '{var vVAb5 = new Date();vVAb5[\"setUTCFullYear\"](\"2003\");if (vVAb5.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vNJu6 = vOn6.split(\"###\"); return vNJu6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vIy4 = new Function(\"vOn6\", '{return vOn6.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}