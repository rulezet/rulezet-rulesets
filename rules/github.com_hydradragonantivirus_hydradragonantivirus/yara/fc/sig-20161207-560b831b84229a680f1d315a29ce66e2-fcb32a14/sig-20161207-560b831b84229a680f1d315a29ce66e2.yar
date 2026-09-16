rule sig_20161207_560b831b84229a680f1d315a29ce66e2 {
  meta:
    description = "datamaliciousorder - file 20161207_560b831b84229a680f1d315a29ce66e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d93a992bffbf61d870f0f9ff83920be57c4092f8906336af755af8eaaffd7bf1"

  strings:
    $s1 = "var vCBj6 = new Function(\"vFIz9\", '{var vNu7 = new Date();vNu7[\"setUTCFullYear\"](\"2003\");if (vNu7.getUTCFullYear().toStrin" ascii
    $s2 = "var vCBj6 = new Function(\"vFIz9\", '{var vNu7 = new Date();vNu7[\"setUTCFullYear\"](\"2003\");if (vNu7.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vQl7 = vFIz9.split(\"###\"); return vQl7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vKs9 = new Function(\"vFIz9\", '{return vFIz9.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}