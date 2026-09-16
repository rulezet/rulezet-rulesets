rule sig_20161207_5e7d5f9fe751f0858e647ffb84cdb56a {
  meta:
    description = "datamaliciousorder - file 20161207_5e7d5f9fe751f0858e647ffb84cdb56a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2421b02d672a772cb115ff88db672c2991201e146001d8866f8efe3b89cf6e0f"

  strings:
    $s1 = "var vKYe3 = new Function(\"vIz5\", '{var vWe1 = new Date();vWe1[\"setUTCFullYear\"](\"2003\");if (vWe1.getUTCFullYear().toString" ascii
    $s2 = "var vKYe3 = new Function(\"vIz5\", '{var vWe1 = new Date();vWe1[\"setUTCFullYear\"](\"2003\");if (vWe1.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vZk2 = vIz5.split(\"###\"); return vZk2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vRo2 = new Function(\"vIz5\", '{return vIz5.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}