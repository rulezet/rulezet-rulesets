rule sig_20161208_8a80ad90d26523fedd714c5c36b06985 {
  meta:
    description = "datamaliciousorder - file 20161208_8a80ad90d26523fedd714c5c36b06985.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1740d946e03ea68c530b4190f533a1876a8cb3f3c056a70b8d638d92fd1536c6"

  strings:
    $s1 = "new Date();vMSx5[\"setUTC\"+\"FullYear\"](\"2003\");if (vMSx5.getUTCFullYear().toString(10) == \"2003\") {var vSAq0 = vHp7.split" ascii
    $s2 = "var vJi9 = new Function(\"vHp7\", '{return vHp7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEb5 = new Function(\"vHp7\"" ascii
    $s3 = "; return vSAq0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vJi9 = new Function(\"vHp7\", '{return vHp7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEb5 = new Function(\"vHp7\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}