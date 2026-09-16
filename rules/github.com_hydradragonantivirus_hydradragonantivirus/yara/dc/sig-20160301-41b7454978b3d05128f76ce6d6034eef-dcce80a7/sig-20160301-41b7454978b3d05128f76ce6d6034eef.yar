rule sig_20160301_41b7454978b3d05128f76ce6d6034eef {
  meta:
    description = "datamaliciousorder - file 20160301_41b7454978b3d05128f76ce6d6034eef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48213ae1a8ff31250b63cdf0542291d4d5565370055f0e14125949d8b7aad428"

  strings:
    $s1 = "while(colossalReporter[(\"re\\u0061dy\\u0073\" + \"\\u0074\\u0061\\u0074\" + \"e\")] < ((2 + 0) ^ (1 + 5))) {" fullword ascii
    $s2 = "\"\\u004f\\u0062\\u006a\\u0065\" + \"c\\u0074\")]((\"\\u0063\" + \"o\\u006cos\" + \"sa\" + \"l\", \"\\u0063\\u006fd\" + \"e\", f" ascii
    $s3 = "colossalReporter = proportionalVocal[(\"\\u0070erm\\u0061\" + \"ne\" + \"n\\u0074\", \"fro\" + \"\\u006e\\u0074\", \"\\u0074ro" ascii
    $s4 = "} catch(complexDollar) {};" fullword ascii
    $s5 = "proportionalVocal = (1, this);" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    all of them
}