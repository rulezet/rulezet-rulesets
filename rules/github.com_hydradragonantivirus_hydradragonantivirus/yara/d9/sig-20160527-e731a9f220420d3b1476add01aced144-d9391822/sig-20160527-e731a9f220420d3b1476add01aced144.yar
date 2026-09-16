rule sig_20160527_e731a9f220420d3b1476add01aced144 {
  meta:
    description = "datamaliciousorder - file 20160527_e731a9f220420d3b1476add01aced144.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fccc327c9d1d3c9f74de39e8d193f2e36dfe577f67d1220773d10e742f748d3"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<adKFg4XUkr.length;i++)if(i%2==0)x.push(adKFg4XUkr[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}