rule sig_20160527_a5074f2c3299caea0492f125a27f9321 {
  meta:
    description = "datamaliciousorder - file 20160527_a5074f2c3299caea0492f125a27f9321.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98ae4a71e21e50f635560a25aeab847bd8d5f57421357cff8e17f9728dbd2d1c"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aVQVF2WMy.length;i++)if(i%2==0)x.push(aVQVF2WMy[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}