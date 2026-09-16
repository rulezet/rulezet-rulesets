rule sig_20161207_5fc143138c38c45e815820504ce2511b {
  meta:
    description = "datamaliciousorder - file 20161207_5fc143138c38c45e815820504ce2511b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29c1f9589368ae826d9b77b9c1268aa994cc4698b57d8061ef4f1d0a30a3c900"

  strings:
    $s1 = "var vZy2 = new Function(\"vTBm6\", '{var vSIx5 = new Date();vSIx5[\"setUTCFullYear\"](\"2003\");if (vSIx5.getUTCFullYear().toStr" ascii
    $s2 = "var vZy2 = new Function(\"vTBm6\", '{var vSIx5 = new Date();vSIx5[\"setUTCFullYear\"](\"2003\");if (vSIx5.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vKDa2 = vTBm6.split(\"###\"); return vKDa2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vITl9 = new Function(\"vTBm6\", '{return vTBm6.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}