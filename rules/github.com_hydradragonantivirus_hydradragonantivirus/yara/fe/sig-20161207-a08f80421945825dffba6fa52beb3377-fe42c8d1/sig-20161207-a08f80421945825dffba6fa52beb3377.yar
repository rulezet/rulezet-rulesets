rule sig_20161207_a08f80421945825dffba6fa52beb3377 {
  meta:
    description = "datamaliciousorder - file 20161207_a08f80421945825dffba6fa52beb3377.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b160a2da710f21c92fb596a081c720bf5e848313c443d5149bb57985a197cbc"

  strings:
    $s1 = " = new Date();vZs7[\"setUTCFullYear\"](\"2003\");if (vZs7.getUTCFullYear().toString(10) == \"2003\") {var vJb7 = vWQn5.split(\"#" ascii
    $s2 = "var vLr2 = new Function(\"vWQn5\", '{return vWQn5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYJp4 = new Function(\"vWQ" ascii
    $s3 = "var vLr2 = new Function(\"vWQn5\", '{return vWQn5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYJp4 = new Function(\"vWQ" ascii
    $s4 = "return vJb7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}