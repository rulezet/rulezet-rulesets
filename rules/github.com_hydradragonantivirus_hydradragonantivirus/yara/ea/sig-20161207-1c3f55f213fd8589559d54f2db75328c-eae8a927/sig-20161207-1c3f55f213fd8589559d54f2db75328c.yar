rule sig_20161207_1c3f55f213fd8589559d54f2db75328c {
  meta:
    description = "datamaliciousorder - file 20161207_1c3f55f213fd8589559d54f2db75328c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c20908a083324be00f65114092bd7a9897eee822bad1599ecd54d2b86198a64"

  strings:
    $s1 = "var vUMw2 = new Function(\"vFXc8\", '{var vNl3 = new Date();vNl3[\"setUTCFullYear\"](\"2003\");if (vNl3.getUTCFullYear().toStrin" ascii
    $s2 = "var vUMw2 = new Function(\"vFXc8\", '{var vNl3 = new Date();vNl3[\"setUTCFullYear\"](\"2003\");if (vNl3.getUTCFullYear().toStrin" ascii
    $s3 = "var vLDr1 = new Function(\"vFXc8\", '{return vFXc8.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vVFk5 = vFXc8.split(\"###\"); return vVFk5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}