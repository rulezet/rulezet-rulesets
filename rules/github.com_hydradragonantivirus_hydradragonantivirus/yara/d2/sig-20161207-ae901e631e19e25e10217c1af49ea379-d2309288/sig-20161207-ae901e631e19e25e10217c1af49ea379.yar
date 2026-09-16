rule sig_20161207_ae901e631e19e25e10217c1af49ea379 {
  meta:
    description = "datamaliciousorder - file 20161207_ae901e631e19e25e10217c1af49ea379.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4907088ed360b020545be206ae27b0f363aa0b43e845b486943d2c92a044dbe6"

  strings:
    $s1 = "var vDXc5 = new Function(\"vNYv6\", '{var vHv2 = new Date();vHv2[\"setUTCFullYear\"](\"2003\");if (vHv2.getUTCFullYear().toStrin" ascii
    $s2 = "var vDXc5 = new Function(\"vNYv6\", '{var vHv2 = new Date();vHv2[\"setUTCFullYear\"](\"2003\");if (vHv2.getUTCFullYear().toStrin" ascii
    $s3 = "var vRu8 = new Function(\"vNYv6\", '{return vNYv6.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vDBp2 = vNYv6.split(\"###\"); return vDBp2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}