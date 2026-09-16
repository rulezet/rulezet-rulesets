rule sig_20160527_0c645d6499af4cefaea36dccafdd87a2 {
  meta:
    description = "datamaliciousorder - file 20160527_0c645d6499af4cefaea36dccafdd87a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b00cc22e77bb8509390b8e75d122ed80763f4ba2bd0592fe7865d76f67e07d3"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<agDCN84.length;i++)if(i%2==0)x.push(agDCN84[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}