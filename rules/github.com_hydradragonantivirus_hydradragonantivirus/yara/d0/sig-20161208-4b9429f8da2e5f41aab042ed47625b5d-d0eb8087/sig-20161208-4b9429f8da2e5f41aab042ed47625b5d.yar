rule sig_20161208_4b9429f8da2e5f41aab042ed47625b5d {
  meta:
    description = "datamaliciousorder - file 20161208_4b9429f8da2e5f41aab042ed47625b5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff7c6d9f3d696599acfa4c077f92b7fefd44b3289c085241a8be76d82ec92bbd"

  strings:
    $s1 = "var vPNv9 = new Function(\"vJSl1\", '{return vJSl1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNj3 = new Function(\"vJS" ascii
    $s2 = " = new Date();vJz7[\"setUTC\"+\"FullYear\"](\"2003\");if (vJz7.getUTCFullYear().toString(10) == \"2003\") {var vHo9 = vJSl1.spli" ascii
    $s3 = "); return vHo9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vPNv9 = new Function(\"vJSl1\", '{return vJSl1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNj3 = new Function(\"vJS" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}