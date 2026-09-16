rule sig_20160527_ca11f0ba59bba064a500df0cc1e4d74c {
  meta:
    description = "datamaliciousorder - file 20160527_ca11f0ba59bba064a500df0cc1e4d74c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b28a9a292407e58aa98b17131c2d19a0b0880b0bebd349a8571c2101bd35ab48"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aF2qeroAF.length;i++)if(i%2==0)x.push(aF2qeroAF[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}