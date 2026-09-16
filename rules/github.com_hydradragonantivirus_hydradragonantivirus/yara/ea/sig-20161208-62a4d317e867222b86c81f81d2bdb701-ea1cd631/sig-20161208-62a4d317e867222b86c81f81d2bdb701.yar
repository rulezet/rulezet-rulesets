rule sig_20161208_62a4d317e867222b86c81f81d2bdb701 {
  meta:
    description = "datamaliciousorder - file 20161208_62a4d317e867222b86c81f81d2bdb701.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96de1089d76d962c4ba3c38b7d812152882671123dfe08e51a8c85a1d3f47861"

  strings:
    $s1 = "var vLf1 = new Function(\"vCt1\", '{return vCt1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGt2 = new Function(\"vCt1\"" ascii
    $s2 = "new Date();vAKt4[\"setUTC\"+\"FullYear\"](\"2003\");if (vAKt4.getUTCFullYear().toString(10) == \"2003\") {var vOIa6 = vCt1.split" ascii
    $s3 = "; return vOIa6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vLf1 = new Function(\"vCt1\", '{return vCt1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGt2 = new Function(\"vCt1\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}