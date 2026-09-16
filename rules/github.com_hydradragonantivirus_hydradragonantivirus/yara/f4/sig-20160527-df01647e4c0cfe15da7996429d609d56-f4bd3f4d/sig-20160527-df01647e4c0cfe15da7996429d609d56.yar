rule sig_20160527_df01647e4c0cfe15da7996429d609d56 {
  meta:
    description = "datamaliciousorder - file 20160527_df01647e4c0cfe15da7996429d609d56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af020d2ea25e2d625f5431fdd204ceadd637a99a419fb082acc788a52b1c7364"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aFp5WpoFQyZ.length;i++)if(i%2==0)x.push(aFp5WpoFQyZ[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}