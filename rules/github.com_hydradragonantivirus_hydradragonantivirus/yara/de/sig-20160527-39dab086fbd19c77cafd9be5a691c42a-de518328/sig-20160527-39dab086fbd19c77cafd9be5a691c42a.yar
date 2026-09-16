rule sig_20160527_39dab086fbd19c77cafd9be5a691c42a {
  meta:
    description = "datamaliciousorder - file 20160527_39dab086fbd19c77cafd9be5a691c42a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1113ed80f5632c0fa56764e60bc105d7680996984914c636f7ceb8524fa4ef74"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aNFdVmtYRjX.length;i++)if(i%2==0)x.push(aNFdVmtYRjX[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}