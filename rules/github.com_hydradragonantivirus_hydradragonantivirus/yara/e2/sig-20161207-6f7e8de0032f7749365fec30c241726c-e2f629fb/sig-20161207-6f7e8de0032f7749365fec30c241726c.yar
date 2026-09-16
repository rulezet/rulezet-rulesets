rule sig_20161207_6f7e8de0032f7749365fec30c241726c {
  meta:
    description = "datamaliciousorder - file 20161207_6f7e8de0032f7749365fec30c241726c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb55606cdb465f28cd77d4c596449423d4e52a27d94b247f0d4c9d0052ce1525"

  strings:
    $s1 = "var vEMq3 = new Function(\"vIMh9\", '{return vIMh9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXt0 = new Function(\"vIM" ascii
    $s2 = "3 = new Date();vJSf3[\"setUTCFullYear\"](\"2003\");if (vJSf3.getUTCFullYear().toString(10) == \"2003\") {var vMYr0 = vIMh9.split" ascii
    $s3 = "var vEMq3 = new Function(\"vIMh9\", '{return vIMh9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXt0 = new Function(\"vIM" ascii
    $s4 = "\"); return vMYr0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}