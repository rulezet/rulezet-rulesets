rule sig_20161207_03d9ec938cb3e076dee48b3176a7d668 {
  meta:
    description = "datamaliciousorder - file 20161207_03d9ec938cb3e076dee48b3176a7d668.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1274f37f777e23496ff18eac5c834c7eecbd7ee49add2bb30913ca16376f7dc7"

  strings:
    $s1 = "var vWa3 = new Function(\"vWa9\", '{var vDt7 = new Date();vDt7[\"setUTCFullYear\"](\"2003\");if (vDt7.getUTCFullYear().toString(" ascii
    $s2 = "var vWa3 = new Function(\"vWa9\", '{var vDt7 = new Date();vDt7[\"setUTCFullYear\"](\"2003\");if (vDt7.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vSo2 = vWa9.split(\"###\"); return vSo2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vUNc7 = new Function(\"vWa9\", '{return vWa9.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}