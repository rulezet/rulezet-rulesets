rule sig_20160527_49dee890964d32321cff92c34b5de9c8 {
  meta:
    description = "datamaliciousorder - file 20160527_49dee890964d32321cff92c34b5de9c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d1c7a0114455dae34b2c4fc700ce732dd6988fede6eea61300eeca917440538"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<acC9LY1QOV0.length;i++)if(i%2==0)x.push(acC9LY1QOV0[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}