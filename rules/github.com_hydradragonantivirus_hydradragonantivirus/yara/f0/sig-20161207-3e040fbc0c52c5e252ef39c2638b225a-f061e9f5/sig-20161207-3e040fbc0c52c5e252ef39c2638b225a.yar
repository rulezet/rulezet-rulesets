rule sig_20161207_3e040fbc0c52c5e252ef39c2638b225a {
  meta:
    description = "datamaliciousorder - file 20161207_3e040fbc0c52c5e252ef39c2638b225a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b66b51e51d30860b578aa672671c0e004d00109b8f19ddd6a4593d2f6f03d56"

  strings:
    $s1 = "var vKQl8 = new Function(\"vTHy1\", '{var vYg8 = new Date();vYg8[\"setUTCFullYear\"](\"2003\");if (vYg8.getUTCFullYear().toStrin" ascii
    $s2 = "var vKQl8 = new Function(\"vTHy1\", '{var vYg8 = new Date();vYg8[\"setUTCFullYear\"](\"2003\");if (vYg8.getUTCFullYear().toStrin" ascii
    $s3 = "var vTUx3 = new Function(\"vTHy1\", '{return vTHy1.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vBv3 = vTHy1.split(\"###\"); return vBv3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}