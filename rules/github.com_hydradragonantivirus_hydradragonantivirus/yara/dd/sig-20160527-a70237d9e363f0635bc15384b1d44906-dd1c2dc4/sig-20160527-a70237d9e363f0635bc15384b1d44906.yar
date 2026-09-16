rule sig_20160527_a70237d9e363f0635bc15384b1d44906 {
  meta:
    description = "datamaliciousorder - file 20160527_a70237d9e363f0635bc15384b1d44906.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbb469b74a5a08f18c8c27515f0af96fdf783cca648924a0477288248cf99dbf"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aCDCI5MRz.length;i++)if(i%2==0)x.push(aCDCI5MRz[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}