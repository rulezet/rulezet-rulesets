rule sig_20161207_d57cf797de6f4433486328ac2cede60d {
  meta:
    description = "datamaliciousorder - file 20161207_d57cf797de6f4433486328ac2cede60d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60e2af6591805d407605f9a9b021069e01f8207f31dac290e9d60144c00f2a21"

  strings:
    $s1 = "var vBi8 = new Function(\"vPJp3\", '{return vPJp3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJb7 = new Function(\"vPJp" ascii
    $s2 = " = new Date();vILh4[\"setUTCFullYear\"](\"2003\");if (vILh4.getUTCFullYear().toString(10) == \"2003\") {var vJu1 = vPJp3.split(" ascii
    $s3 = "; return vJu1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vBi8 = new Function(\"vPJp3\", '{return vPJp3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJb7 = new Function(\"vPJp" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}