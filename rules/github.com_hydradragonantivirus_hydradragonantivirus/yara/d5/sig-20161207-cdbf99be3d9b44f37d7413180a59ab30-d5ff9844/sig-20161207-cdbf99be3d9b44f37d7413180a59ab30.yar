rule sig_20161207_cdbf99be3d9b44f37d7413180a59ab30 {
  meta:
    description = "datamaliciousorder - file 20161207_cdbf99be3d9b44f37d7413180a59ab30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdc7d9c364762acc51e1a10775428b71550ae42dff3bcad974966e0d07fa466f"

  strings:
    $s1 = "var vNKc1 = new Function(\"vEAh5\", '{var vBHj6 = new Date();vBHj6[\"setUTCFullYear\"](\"2003\");if (vBHj6.getUTCFullYear().toSt" ascii
    $s2 = "var vNKc1 = new Function(\"vEAh5\", '{var vBHj6 = new Date();vBHj6[\"setUTCFullYear\"](\"2003\");if (vBHj6.getUTCFullYear().toSt" ascii
    $s3 = "var vUQq8 = new Function(\"vEAh5\", '{return vEAh5.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "0) == \"2003\") {var vUe1 = vEAh5.split(\"###\"); return vUe1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}