rule sig_20161208_08ed0ad10b90ff452de5d9ee395b77cf {
  meta:
    description = "datamaliciousorder - file 20161208_08ed0ad10b90ff452de5d9ee395b77cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96dfe3d2a2ab097bf50b3ad417c50c70343af58bdd972fccd0cbe78fe20a50f2"

  strings:
    $s1 = " new Date();vOt4[\"setUTC\"+\"FullYear\"](\"2003\");if (vOt4.getUTCFullYear().toString(10) == \"2003\") {var vVs6 = vGg8.split(" ascii
    $s2 = "var vVGg4 = new Function(\"vGg8\", '{return vGg8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vABi4 = new Function(\"vGg8" ascii
    $s3 = "var vVGg4 = new Function(\"vGg8\", '{return vGg8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vABi4 = new Function(\"vGg8" ascii
    $s4 = "return vVs6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}