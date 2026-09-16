rule sig_20161207_2eaca7a7b212fea0ac6fcba4e7c0f574 {
  meta:
    description = "datamaliciousorder - file 20161207_2eaca7a7b212fea0ac6fcba4e7c0f574.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "426944618f3be3a70a101181701e3228a34539c711f659de5f84257a99cd62de"

  strings:
    $s1 = "var vLy1 = new Function(\"vGYt3\", '{var vJDr2 = new Date();vJDr2[\"setUTCFullYear\"](\"2003\");if (vJDr2.getUTCFullYear().toStr" ascii
    $s2 = "var vLy1 = new Function(\"vGYt3\", '{var vJDr2 = new Date();vJDr2[\"setUTCFullYear\"](\"2003\");if (vJDr2.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vUVl3 = vGYt3.split(\"###\"); return vUVl3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vIMc0 = new Function(\"vGYt3\", '{return vGYt3.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}