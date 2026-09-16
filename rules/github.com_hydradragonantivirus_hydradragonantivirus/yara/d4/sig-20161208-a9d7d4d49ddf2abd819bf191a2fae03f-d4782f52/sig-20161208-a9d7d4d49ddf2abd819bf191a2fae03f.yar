rule sig_20161208_a9d7d4d49ddf2abd819bf191a2fae03f {
  meta:
    description = "datamaliciousorder - file 20161208_a9d7d4d49ddf2abd819bf191a2fae03f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc8a4bbcc8ee87027b0c08840eadfb8891b885fb90dba45c401c1dd6cbbb28eb"

  strings:
    $s1 = "7 = new Date();vPBu7[\"setUTC\"+\"FullYear\"](\"2003\");if (vPBu7.getUTCFullYear().toString(10) == \"2003\") {var vFr8 = vTPd1.s" ascii
    $s2 = "var vDw0 = new Function(\"vTPd1\", '{return vTPd1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSZj2 = new Function(\"vTP" ascii
    $s3 = "##\"); return vFr8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vDw0 = new Function(\"vTPd1\", '{return vTPd1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSZj2 = new Function(\"vTP" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}