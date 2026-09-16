rule sig_20161208_77fa716a9a5fa1fac9259c04e2e21bd5 {
  meta:
    description = "datamaliciousorder - file 20161208_77fa716a9a5fa1fac9259c04e2e21bd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14e3d0d81d1faaaed01472ace5fc8e00e3224764578dfff2021d56aabb3807fb"

  strings:
    $s1 = "5 = new Date();vBKc5[\"setUTC\"+\"FullYear\"](\"2003\");if (vBKc5.getUTCFullYear().toString(10) == \"2003\") {var vVWv5 = vWb00." ascii
    $s2 = "var vTUd6 = new Function(\"vWb00\", '{return vWb00[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKq7 = new Function(\"vWb" ascii
    $s3 = "###\"); return vVWv5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vTUd6 = new Function(\"vWb00\", '{return vWb00[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKq7 = new Function(\"vWb" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}