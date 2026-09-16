rule sig_20161207_8309f17c0c3d7b70e91f20071efe6094 {
  meta:
    description = "datamaliciousorder - file 20161207_8309f17c0c3d7b70e91f20071efe6094.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13d42636df04b5ceebbbbc0942724bf85c0ab041b559b1a45f7784dc081b0ae1"

  strings:
    $s1 = "var vWAe6 = new Function(\"vMWb1\", '{var vANz8 = new Date();vANz8[\"setUTCFullYear\"](\"2003\");if (vANz8.getUTCFullYear().toSt" ascii
    $s2 = "var vWAe6 = new Function(\"vMWb1\", '{var vANz8 = new Date();vANz8[\"setUTCFullYear\"](\"2003\");if (vANz8.getUTCFullYear().toSt" ascii
    $s3 = "var vYg5 = new Function(\"vMWb1\", '{return vMWb1.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "0) == \"2003\") {var vSYs2 = vMWb1.split(\"###\"); return vSYs2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}