rule sig_20160527_7d067afdf6005a8619fa816f16db8d6a {
  meta:
    description = "datamaliciousorder - file 20160527_7d067afdf6005a8619fa816f16db8d6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "959510f095d2656227bde91880ee1f1276896685b67ed29b7c3b9d6489801cbb"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aokw8KI.length;i++)if(i%2==0)x.push(aokw8KI[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}