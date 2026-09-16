rule sig_20161208_9da1aeb7bc32266a2db4282498bb15ee {
  meta:
    description = "datamaliciousorder - file 20161208_9da1aeb7bc32266a2db4282498bb15ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de6f908c8081c4d32320b4709a68b412cbd45313633ef7f1d8a11d9fd26018b2"

  strings:
    $s1 = "var vZIe4 = new Function(\"vWTm9\", '{return vWTm9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCf0 = new Function(\"vWT" ascii
    $s2 = "7 = new Date();vKQw7[\"setUTC\"+\"FullYear\"](\"2003\");if (vKQw7.getUTCFullYear().toString(10) == \"2003\") {var vAOv1 = vWTm9." ascii
    $s3 = "###\"); return vAOv1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vZIe4 = new Function(\"vWTm9\", '{return vWTm9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCf0 = new Function(\"vWT" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}