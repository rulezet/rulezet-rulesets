rule sig_20161208_2385a6d08c69f2e5a578e3431a73871b {
  meta:
    description = "datamaliciousorder - file 20161208_2385a6d08c69f2e5a578e3431a73871b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b5d41ffef24233729be7e84b662b4a5a6b6838a61f7f46a3cefb2fc8290e974"

  strings:
    $s1 = "= new Date();vDa3[\"setUTC\"+\"FullYear\"](\"2003\");if (vDa3.getUTCFullYear().toString(10) == \"2003\") {var vAQy7 = vMDf8.spli" ascii
    $s2 = "var vNf1 = new Function(\"vMDf8\", '{return vMDf8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTu9 = new Function(\"vMDf" ascii
    $s3 = "); return vAQy7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vNf1 = new Function(\"vMDf8\", '{return vMDf8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTu9 = new Function(\"vMDf" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}