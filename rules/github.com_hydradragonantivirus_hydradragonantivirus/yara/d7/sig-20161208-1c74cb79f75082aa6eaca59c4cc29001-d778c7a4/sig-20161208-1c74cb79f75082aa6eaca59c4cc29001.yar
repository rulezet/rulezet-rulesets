rule sig_20161208_1c74cb79f75082aa6eaca59c4cc29001 {
  meta:
    description = "datamaliciousorder - file 20161208_1c74cb79f75082aa6eaca59c4cc29001.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b67b10f0a9f3160854b5024c6f7d51e7172f982f781d83e555991f3554ab557c"

  strings:
    $s1 = "new Date();vFa8[\"setUTC\"+\"FullYear\"](\"2003\");if (vFa8.getUTCFullYear().toString(10) == \"2003\") {var vYCn5 = vKb5.split(" ascii
    $s2 = "var vCw6 = new Function(\"vKb5\", '{return vKb5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAUz6 = new Function(\"vKb5" ascii
    $s3 = "return vYCn5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vCw6 = new Function(\"vKb5\", '{return vKb5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAUz6 = new Function(\"vKb5" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}