rule sig_20161208_a3ea702f1c3f9b800eb8ca20f1b54638 {
  meta:
    description = "datamaliciousorder - file 20161208_a3ea702f1c3f9b800eb8ca20f1b54638.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41228e51a34812d69b66932a56430f331d149a42156b65f18a02f07deeb55fdc"

  strings:
    $s1 = "t7 = new Date();vJNt7[\"setUTC\"+\"FullYear\"](\"2003\");if (vJNt7.getUTCFullYear().toString(10) == \"2003\") {var vUm1 = vZWn4." ascii
    $s2 = "var vWJt3 = new Function(\"vZWn4\", '{return vZWn4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAMj5 = new Function(\"vZ" ascii
    $s3 = "###\"); return vUm1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vWJt3 = new Function(\"vZWn4\", '{return vZWn4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAMj5 = new Function(\"vZ" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}