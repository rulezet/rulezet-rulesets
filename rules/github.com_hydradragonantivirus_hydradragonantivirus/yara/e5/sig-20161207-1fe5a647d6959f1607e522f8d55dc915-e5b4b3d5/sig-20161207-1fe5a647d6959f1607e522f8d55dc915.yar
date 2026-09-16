rule sig_20161207_1fe5a647d6959f1607e522f8d55dc915 {
  meta:
    description = "datamaliciousorder - file 20161207_1fe5a647d6959f1607e522f8d55dc915.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e76af762cb0e56f55dc070194e404fb7044b9bcc5afd3adfc069b60bdef2a724"

  strings:
    $s1 = "p7 = new Date();vYJp7[\"setUTCFullYear\"](\"2003\");if (vYJp7.getUTCFullYear().toString(10) == \"2003\") {var vLi2 = vOGp1.split" ascii
    $s2 = "var vVXy2 = new Function(\"vOGp1\", '{return vOGp1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYAz8 = new Function(\"vO" ascii
    $s3 = "var vVXy2 = new Function(\"vOGp1\", '{return vOGp1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYAz8 = new Function(\"vO" ascii
    $s4 = "\"); return vLi2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}