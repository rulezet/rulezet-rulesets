rule sig_20160527_c09817a52c524dfe000099d0d13fb4d5 {
  meta:
    description = "datamaliciousorder - file 20160527_c09817a52c524dfe000099d0d13fb4d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2ee719231eb207fef700e3d54f23402be284dbffcbfb5d7c368a5e7c5bda269"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aKWXixuZNAE.length;i++)if(i%2==0)x.push(aKWXixuZNAE[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}