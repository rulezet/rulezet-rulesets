rule sig_20161208_7e8642538a5d1ab33245ce9064dd71fc {
  meta:
    description = "datamaliciousorder - file 20161208_7e8642538a5d1ab33245ce9064dd71fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da57c6d8f30bf02d2cf582994a5325d78411233fd19bb2e3f624c3235ffffedc"

  strings:
    $s1 = "var vVj8 = new Function(\"vLn1\", '{return vLn1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIr8 = new Function(\"vLn1\"" ascii
    $s2 = "ew Date();vRp4[\"setUTC\"+\"FullYear\"](\"2003\");if (vRp4.getUTCFullYear().toString(10) == \"2003\") {var vCm7 = vLn1.split(\"#" ascii
    $s3 = "turn vCm7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vVj8 = new Function(\"vLn1\", '{return vLn1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIr8 = new Function(\"vLn1\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}