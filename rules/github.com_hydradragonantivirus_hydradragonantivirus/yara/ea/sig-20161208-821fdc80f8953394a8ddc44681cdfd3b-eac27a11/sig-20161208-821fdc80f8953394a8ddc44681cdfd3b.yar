rule sig_20161208_821fdc80f8953394a8ddc44681cdfd3b {
  meta:
    description = "datamaliciousorder - file 20161208_821fdc80f8953394a8ddc44681cdfd3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db337c985885c7686e8eea5710dc5f0df1ce440f122fd52150ad7145209d1ef7"

  strings:
    $s1 = "var vPMr5 = new Function(\"vOe2\", '{return vOe2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOTz7 = new Function(\"vOe2" ascii
    $s2 = " new Date();vCr4[\"setUTC\"+\"FullYear\"](\"2003\");if (vCr4.getUTCFullYear().toString(10) == \"2003\") {var vOd9 = vOe2.split(" ascii
    $s3 = "return vOd9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vPMr5 = new Function(\"vOe2\", '{return vOe2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOTz7 = new Function(\"vOe2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}