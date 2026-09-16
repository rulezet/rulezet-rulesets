rule sig_20161207_d38232dbde475be4be30f134481606ef {
  meta:
    description = "datamaliciousorder - file 20161207_d38232dbde475be4be30f134481606ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01e12ae19c6acc7e532adaa5d15bfdcea96230c97b9470975c3f107693478716"

  strings:
    $s1 = "var vLi8 = new Function(\"vXYk4\", '{return vXYk4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLf7 = new Function(\"vXYk" ascii
    $s2 = " = new Date();vBOv9[\"setUTCFullYear\"](\"2003\");if (vBOv9.getUTCFullYear().toString(10) == \"2003\") {var vYJn9 = vXYk4.split(" ascii
    $s3 = "var vLi8 = new Function(\"vXYk4\", '{return vXYk4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLf7 = new Function(\"vXYk" ascii
    $s4 = "); return vYJn9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}