rule sig_20161207_dbbdfc3ae94a1b6d1ce8a1a91beaec45 {
  meta:
    description = "datamaliciousorder - file 20161207_dbbdfc3ae94a1b6d1ce8a1a91beaec45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4422c4af71acaedfd706b79e0ca8d6c7687d5218d3011cf95c17c5917a16011"

  strings:
    $s1 = "var vUo5 = new Function(\"vHNq9\", '{var vMDb8 = new Date();vMDb8[\"setUTCFullYear\"](\"2003\");if (vMDb8.getUTCFullYear().toStr" ascii
    $s2 = "var vUo5 = new Function(\"vHNq9\", '{var vMDb8 = new Date();vMDb8[\"setUTCFullYear\"](\"2003\");if (vMDb8.getUTCFullYear().toStr" ascii
    $s3 = "var vJo7 = new Function(\"vHNq9\", '{return vHNq9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vKXn3 = vHNq9.split(\"###\"); return vKXn3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}