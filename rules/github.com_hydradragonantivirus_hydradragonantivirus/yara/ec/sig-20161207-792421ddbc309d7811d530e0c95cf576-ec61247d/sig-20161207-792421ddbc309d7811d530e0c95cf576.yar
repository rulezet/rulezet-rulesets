rule sig_20161207_792421ddbc309d7811d530e0c95cf576 {
  meta:
    description = "datamaliciousorder - file 20161207_792421ddbc309d7811d530e0c95cf576.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a428603fc32a8916246100c1f0ca51fc6f305b7d4a74ca10b41bf3e568a6280b"

  strings:
    $s1 = "var vUf4 = new Function(\"vQQe3\", '{var vBQb1 = new Date();vBQb1[\"setUTCFullYear\"](\"2003\");if (vBQb1.getUTCFullYear().toStr" ascii
    $s2 = "var vUf4 = new Function(\"vQQe3\", '{var vBQb1 = new Date();vBQb1[\"setUTCFullYear\"](\"2003\");if (vBQb1.getUTCFullYear().toStr" ascii
    $s3 = "var vWa0 = new Function(\"vQQe3\", '{return vQQe3.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vTNi6 = vQQe3.split(\"###\"); return vTNi6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}