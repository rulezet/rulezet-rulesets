rule sig_20161207_416267ac1acc11bdc22b37fc9513a7be {
  meta:
    description = "datamaliciousorder - file 20161207_416267ac1acc11bdc22b37fc9513a7be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7845902d6931fae712a9dce62d6399832db352cbdac3eb4df928d8c9afe0c7b2"

  strings:
    $s1 = " = new Date();vCh2[\"setUTCFullYear\"](\"2003\");if (vCh2.getUTCFullYear().toString(10) == \"2003\") {var vXi5 = vRGc1.split(\"#" ascii
    $s2 = "var vWa5 = new Function(\"vRGc1\", '{return vRGc1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSRd1 = new Function(\"vRG" ascii
    $s3 = "var vWa5 = new Function(\"vRGc1\", '{return vRGc1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSRd1 = new Function(\"vRG" ascii
    $s4 = "return vXi5.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}