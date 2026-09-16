rule sig_20161208_d98e9d59f40327d6a9c303f888ea874a {
  meta:
    description = "datamaliciousorder - file 20161208_d98e9d59f40327d6a9c303f888ea874a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdd533322aa5fa9e86f88abf05ca3413bb6a8def0c603e41a63d6f36d47d93f4"

  strings:
    $s1 = "var vKLn9 = new Function(\"vDo5\", '{return vDo5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTAa3 = new Function(\"vDo5" ascii
    $s2 = " new Date();vVk2[\"setUTC\"+\"FullYear\"](\"2003\");if (vVk2.getUTCFullYear().toString(10) == \"2003\") {var vBy9 = vDo5.split(" ascii
    $s3 = "var vKLn9 = new Function(\"vDo5\", '{return vDo5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTAa3 = new Function(\"vDo5" ascii
    $s4 = "return vBy9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}