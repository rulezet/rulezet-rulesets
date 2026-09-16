rule sig_20160527_f3f6a5a0ab16056ea3a338660bb26131 {
  meta:
    description = "datamaliciousorder - file 20160527_f3f6a5a0ab16056ea3a338660bb26131.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ddb8be66f9511387ed3c894716d1e07067e2d421aa112de5bba5725087b321c"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a6HmYuMya.length;i++)if(i%2==0)x.push(a6HmYuMya[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}