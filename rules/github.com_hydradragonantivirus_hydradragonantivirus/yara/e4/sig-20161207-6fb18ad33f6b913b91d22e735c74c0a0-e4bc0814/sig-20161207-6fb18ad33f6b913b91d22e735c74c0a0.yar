rule sig_20161207_6fb18ad33f6b913b91d22e735c74c0a0 {
  meta:
    description = "datamaliciousorder - file 20161207_6fb18ad33f6b913b91d22e735c74c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90fdc99f7652562e092890927d13a32ab12c2185177f9ac64c1d8a5fccaea089"

  strings:
    $s1 = "var vZe3 = new Function(\"vHWl6\", '{return vHWl6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNUi3 = new Function(\"vHW" ascii
    $s2 = "5 = new Date();vBUc5[\"setUTCFullYear\"](\"2003\");if (vBUc5.getUTCFullYear().toString(10) == \"2003\") {var vZXk5 = vHWl6.split" ascii
    $s3 = "\"); return vZXk5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vZe3 = new Function(\"vHWl6\", '{return vHWl6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNUi3 = new Function(\"vHW" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}