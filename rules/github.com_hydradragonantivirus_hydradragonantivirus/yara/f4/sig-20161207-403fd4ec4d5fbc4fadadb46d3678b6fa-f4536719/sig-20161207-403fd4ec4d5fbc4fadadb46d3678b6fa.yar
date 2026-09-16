rule sig_20161207_403fd4ec4d5fbc4fadadb46d3678b6fa {
  meta:
    description = "datamaliciousorder - file 20161207_403fd4ec4d5fbc4fadadb46d3678b6fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36a141702d59af245e234f21c5422439414520da4ce2a37207e05571fedb9dc3"

  strings:
    $s1 = "var vOa7 = new Function(\"vTu9\", '{var vEv0 = new Date();vEv0[\"setUTCFullYear\"](\"2003\");if (vEv0.getUTCFullYear().toString(" ascii
    $s2 = "var vOa7 = new Function(\"vTu9\", '{var vEv0 = new Date();vEv0[\"setUTCFullYear\"](\"2003\");if (vEv0.getUTCFullYear().toString(" ascii
    $s3 = "var vSo1 = new Function(\"vTu9\", '{return vTu9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vMk8 = vTu9.split(\"###\"); return vMk8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}