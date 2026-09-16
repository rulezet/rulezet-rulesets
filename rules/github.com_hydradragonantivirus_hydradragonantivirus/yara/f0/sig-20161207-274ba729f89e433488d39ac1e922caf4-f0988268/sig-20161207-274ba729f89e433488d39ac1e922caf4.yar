rule sig_20161207_274ba729f89e433488d39ac1e922caf4 {
  meta:
    description = "datamaliciousorder - file 20161207_274ba729f89e433488d39ac1e922caf4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68c7b1263daf0730af771e2aeb4fa44e26609a679b90a30524bcf12079e7aeff"

  strings:
    $s1 = "var vPz2 = new Function(\"vANj0\", '{var vSa0 = new Date();vSa0[\"setUTCFullYear\"](\"2003\");if (vSa0.getUTCFullYear().toString" ascii
    $s2 = "var vPz2 = new Function(\"vANj0\", '{var vSa0 = new Date();vSa0[\"setUTCFullYear\"](\"2003\");if (vSa0.getUTCFullYear().toString" ascii
    $s3 = "var vNr4 = new Function(\"vANj0\", '{return vANj0.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vJr0 = vANj0.split(\"###\"); return vJr0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}