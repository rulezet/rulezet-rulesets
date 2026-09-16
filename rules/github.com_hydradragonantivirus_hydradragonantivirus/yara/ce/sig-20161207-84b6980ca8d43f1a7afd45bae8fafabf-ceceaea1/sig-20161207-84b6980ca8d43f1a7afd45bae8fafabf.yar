rule sig_20161207_84b6980ca8d43f1a7afd45bae8fafabf {
  meta:
    description = "datamaliciousorder - file 20161207_84b6980ca8d43f1a7afd45bae8fafabf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11b138648b1578c1909dba8ac0e4cdd18f24410443d082a4774daa38ca4c6acb"

  strings:
    $s1 = "var vLRa8 = new Function(\"vBf7\", '{var vPDr0 = new Date();vPDr0[\"setUTCFullYear\"](\"2003\");if (vPDr0.getUTCFullYear().toStr" ascii
    $s2 = "var vLRa8 = new Function(\"vBf7\", '{var vPDr0 = new Date();vPDr0[\"setUTCFullYear\"](\"2003\");if (vPDr0.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vTz5 = vBf7.split(\"###\"); return vTz5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vSDv7 = new Function(\"vBf7\", '{return vBf7.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}