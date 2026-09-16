rule sig_20161207_3b00aa150fc44e4ecdc7794feca457ac {
  meta:
    description = "datamaliciousorder - file 20161207_3b00aa150fc44e4ecdc7794feca457ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6e4f786921d7bafda9cf3b2a3c11884538fe958dda13faf798ed8cdfaf327f7"

  strings:
    $s1 = "var vGCa3 = new Function(\"vFZl1\", '{var vTBn1 = new Date();vTBn1[\"setUTCFullYear\"](\"2003\");if (vTBn1.getUTCFullYear().toSt" ascii
    $s2 = "var vGCa3 = new Function(\"vFZl1\", '{var vTBn1 = new Date();vTBn1[\"setUTCFullYear\"](\"2003\");if (vTBn1.getUTCFullYear().toSt" ascii
    $s3 = "0) == \"2003\") {var vXl1 = vFZl1.split(\"###\"); return vXl1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vLy7 = new Function(\"vFZl1\", '{return vFZl1.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}