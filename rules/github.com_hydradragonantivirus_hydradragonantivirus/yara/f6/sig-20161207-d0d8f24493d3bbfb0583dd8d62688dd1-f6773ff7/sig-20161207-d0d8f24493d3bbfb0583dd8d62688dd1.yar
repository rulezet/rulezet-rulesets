rule sig_20161207_d0d8f24493d3bbfb0583dd8d62688dd1 {
  meta:
    description = "datamaliciousorder - file 20161207_d0d8f24493d3bbfb0583dd8d62688dd1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc43ef26f5818817c3ae9b7a27396d9381a1d8316984f428e8122935e02da6cb"

  strings:
    $s1 = "var vYh2 = new Function(\"vCh8\", '{var vNMi0 = new Date();vNMi0[\"setUTCFullYear\"](\"2003\");if (vNMi0.getUTCFullYear().toStri" ascii
    $s2 = "var vYh2 = new Function(\"vCh8\", '{var vNMi0 = new Date();vNMi0[\"setUTCFullYear\"](\"2003\");if (vNMi0.getUTCFullYear().toStri" ascii
    $s3 = "var vYk9 = new Function(\"vCh8\", '{return vCh8.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " == \"2003\") {var vOIn5 = vCh8.split(\"###\"); return vOIn5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}