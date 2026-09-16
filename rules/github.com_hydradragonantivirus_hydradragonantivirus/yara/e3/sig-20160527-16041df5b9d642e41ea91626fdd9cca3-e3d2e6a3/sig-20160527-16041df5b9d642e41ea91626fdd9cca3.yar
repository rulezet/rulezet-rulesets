rule sig_20160527_16041df5b9d642e41ea91626fdd9cca3 {
  meta:
    description = "datamaliciousorder - file 20160527_16041df5b9d642e41ea91626fdd9cca3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3609da03203ec81fa9047375230c4c88fbce9a1f050da4ae159fa3b215ba32ff"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<ammlOti.length;i++)if(i%2==0)x.push(ammlOti[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}