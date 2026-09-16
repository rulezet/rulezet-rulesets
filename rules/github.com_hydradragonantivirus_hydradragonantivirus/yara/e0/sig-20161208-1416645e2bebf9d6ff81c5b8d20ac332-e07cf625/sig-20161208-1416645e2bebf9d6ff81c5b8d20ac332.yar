rule sig_20161208_1416645e2bebf9d6ff81c5b8d20ac332 {
  meta:
    description = "datamaliciousorder - file 20161208_1416645e2bebf9d6ff81c5b8d20ac332.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2d33e5fadb83b29fd1b8a603b1a97f9c41018797c745442828b2aaa2a75344f"

  strings:
    $s1 = "7 = new Date();vLWq7[\"setUTC\"+\"FullYear\"](\"2003\");if (vLWq7.getUTCFullYear().toString(10) == \"2003\") {var vId0 = vULc7.s" ascii
    $s2 = "var vYk8 = new Function(\"vULc7\", '{return vULc7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDUk8 = new Function(\"vUL" ascii
    $s3 = "##\"); return vId0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vYk8 = new Function(\"vULc7\", '{return vULc7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDUk8 = new Function(\"vUL" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}