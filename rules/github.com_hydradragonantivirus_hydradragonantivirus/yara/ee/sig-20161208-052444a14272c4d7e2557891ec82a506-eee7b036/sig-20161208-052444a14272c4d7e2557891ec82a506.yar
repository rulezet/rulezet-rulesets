rule sig_20161208_052444a14272c4d7e2557891ec82a506 {
  meta:
    description = "datamaliciousorder - file 20161208_052444a14272c4d7e2557891ec82a506.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bcd540d9f4dea38a4434b76e96eab1bd2dd9c49bb434aae19e3472c63ca51524"

  strings:
    $s1 = "var vWBf0 = new Function(\"vUh2\", '{return vUh2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYAv8 = new Function(\"vUh2" ascii
    $s2 = " new Date();vVh1[\"setUTC\"+\"FullYear\"](\"2003\");if (vVh1.getUTCFullYear().toString(10) == \"2003\") {var vCFt9 = vUh2.split(" ascii
    $s3 = " return vCFt9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vWBf0 = new Function(\"vUh2\", '{return vUh2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYAv8 = new Function(\"vUh2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}