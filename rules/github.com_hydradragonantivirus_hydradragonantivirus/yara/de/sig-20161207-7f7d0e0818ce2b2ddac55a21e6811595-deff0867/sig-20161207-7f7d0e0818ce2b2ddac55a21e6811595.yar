rule sig_20161207_7f7d0e0818ce2b2ddac55a21e6811595 {
  meta:
    description = "datamaliciousorder - file 20161207_7f7d0e0818ce2b2ddac55a21e6811595.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af59a10238c986288b0ce11af0819886f3279a9f9a75e1923d6541af907b064a"

  strings:
    $s1 = "var vXWi2 = new Function(\"vNa3\", '{return vNa3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSVj0 = new Function(\"vNa3" ascii
    $s2 = "= new Date();vGMx5[\"setUTCFullYear\"](\"2003\");if (vGMx5.getUTCFullYear().toString(10) == \"2003\") {var vZg4 = vNa3.split(\"#" ascii
    $s3 = "var vXWi2 = new Function(\"vNa3\", '{return vNa3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSVj0 = new Function(\"vNa3" ascii
    $s4 = "return vZg4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}