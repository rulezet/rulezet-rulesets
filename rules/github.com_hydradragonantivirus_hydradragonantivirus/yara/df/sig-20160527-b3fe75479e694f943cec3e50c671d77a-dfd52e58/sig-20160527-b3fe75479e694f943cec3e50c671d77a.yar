rule sig_20160527_b3fe75479e694f943cec3e50c671d77a {
  meta:
    description = "datamaliciousorder - file 20160527_b3fe75479e694f943cec3e50c671d77a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ac6cf419b1ac21bd3f7053f4dd00f224c4f1ea09c9fba784446919def832ab6"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<acW2agAAg.length;i++)if(i%2==0)x.push(acW2agAAg[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}