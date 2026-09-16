rule sig_20161207_bce8a09e49fd091a969d13ff6eece21e {
  meta:
    description = "datamaliciousorder - file 20161207_bce8a09e49fd091a969d13ff6eece21e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "724fbcefef0413c174ac633b5fd48ef3ae005fbb710a0d5e8d7483d3ae9ea288"

  strings:
    $s1 = "var vZGs3 = new Function(\"vJVm9\", '{var vVt1 = new Date();vVt1[\"setUTCFullYear\"](\"2003\");if (vVt1.getUTCFullYear().toStrin" ascii
    $s2 = "var vZGs3 = new Function(\"vJVm9\", '{var vVt1 = new Date();vVt1[\"setUTCFullYear\"](\"2003\");if (vVt1.getUTCFullYear().toStrin" ascii
    $s3 = "var vGFn6 = new Function(\"vJVm9\", '{return vJVm9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vYLw8 = vJVm9.split(\"###\"); return vYLw8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}