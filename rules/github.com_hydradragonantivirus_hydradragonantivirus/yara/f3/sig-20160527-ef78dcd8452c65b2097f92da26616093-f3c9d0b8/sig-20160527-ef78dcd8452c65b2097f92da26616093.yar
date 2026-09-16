rule sig_20160527_ef78dcd8452c65b2097f92da26616093 {
  meta:
    description = "datamaliciousorder - file 20160527_ef78dcd8452c65b2097f92da26616093.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c712b1e1d1ded84800f3fe9bd0a03f2d2342e09325be768efef563039368e81f"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aIxNZ7zcfJ.length;i++)if(i%2==0)x.push(aIxNZ7zcfJ[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}