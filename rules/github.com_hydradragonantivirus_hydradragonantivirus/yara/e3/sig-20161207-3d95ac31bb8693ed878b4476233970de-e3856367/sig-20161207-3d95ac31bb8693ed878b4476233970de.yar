rule sig_20161207_3d95ac31bb8693ed878b4476233970de {
  meta:
    description = "datamaliciousorder - file 20161207_3d95ac31bb8693ed878b4476233970de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5593bd269359f2406ebe387f236bcaf004af06bc9f3eb6447a63f9f59c32ba7"

  strings:
    $s1 = "var vOj9 = new Function(\"vWHl8\", '{var vPv8 = new Date();vPv8[\"setUTCFullYear\"](\"2003\");if (vPv8.getUTCFullYear().toString" ascii
    $s2 = "var vOj9 = new Function(\"vWHl8\", '{var vPv8 = new Date();vPv8[\"setUTCFullYear\"](\"2003\");if (vPv8.getUTCFullYear().toString" ascii
    $s3 = "var vGa1 = new Function(\"vWHl8\", '{return vWHl8.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vFk4 = vWHl8.split(\"###\"); return vFk4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}