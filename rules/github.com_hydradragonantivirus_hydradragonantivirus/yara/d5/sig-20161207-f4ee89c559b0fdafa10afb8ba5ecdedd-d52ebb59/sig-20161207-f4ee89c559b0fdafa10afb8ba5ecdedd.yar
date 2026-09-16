rule sig_20161207_f4ee89c559b0fdafa10afb8ba5ecdedd {
  meta:
    description = "datamaliciousorder - file 20161207_f4ee89c559b0fdafa10afb8ba5ecdedd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dc86d9c6496c174f668cf499c693614e5d9ad13a011ab5f315f835322115224"

  strings:
    $s1 = "var vETv0 = new Function(\"vYKc0\", '{var vVFv3 = new Date();vVFv3[\"setUTCFullYear\"](\"2003\");if (vVFv3.getUTCFullYear().toSt" ascii
    $s2 = "var vETv0 = new Function(\"vYKc0\", '{var vVFv3 = new Date();vVFv3[\"setUTCFullYear\"](\"2003\");if (vVFv3.getUTCFullYear().toSt" ascii
    $s3 = "0) == \"2003\") {var vOEm1 = vYKc0.split(\"###\"); return vOEm1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vSz1 = new Function(\"vYKc0\", '{return vYKc0.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}