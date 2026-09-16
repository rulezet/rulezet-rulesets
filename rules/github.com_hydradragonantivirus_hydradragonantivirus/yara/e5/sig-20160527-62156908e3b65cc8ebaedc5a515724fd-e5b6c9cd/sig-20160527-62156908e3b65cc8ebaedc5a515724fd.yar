rule sig_20160527_62156908e3b65cc8ebaedc5a515724fd {
  meta:
    description = "datamaliciousorder - file 20160527_62156908e3b65cc8ebaedc5a515724fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c983fad5d9db0b2e4a1842ab289d33674cf513aaea2e2f6fd84cb95cb38200aa"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a8g06y3ry7.length;i++)if(i%2==0)x.push(a8g06y3ry7[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}