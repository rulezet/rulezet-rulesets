rule sig_20161207_d6835dd3ac37ffc9bd50b953829232c5 {
  meta:
    description = "datamaliciousorder - file 20161207_d6835dd3ac37ffc9bd50b953829232c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed8ad894d13b3618908bfe18a1c7abf09a9c477d6c00373ce38a350de29abe73"

  strings:
    $s1 = "var vGNd2 = new Function(\"vDx4\", '{var vEn3 = new Date();vEn3[\"setUTCFullYear\"](\"2003\");if (vEn3.getUTCFullYear().toString" ascii
    $s2 = "var vGNd2 = new Function(\"vDx4\", '{var vEn3 = new Date();vEn3[\"setUTCFullYear\"](\"2003\");if (vEn3.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vSi3 = vDx4.split(\"###\"); return vSi3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vOe7 = new Function(\"vDx4\", '{return vDx4.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}