rule sig_20160527_5dcc5471600e4707475bcdefb04135cf {
  meta:
    description = "datamaliciousorder - file 20160527_5dcc5471600e4707475bcdefb04135cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c20055e7383dbd92a9af6e0d1963d30a3a539c9d050d808cd62ead95ac5c7643"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aEXHfgP.length;i++)if(i%2==0)x.push(aEXHfgP[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}