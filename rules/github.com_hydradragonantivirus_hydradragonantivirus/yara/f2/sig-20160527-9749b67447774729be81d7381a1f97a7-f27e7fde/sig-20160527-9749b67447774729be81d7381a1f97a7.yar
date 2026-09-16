rule sig_20160527_9749b67447774729be81d7381a1f97a7 {
  meta:
    description = "datamaliciousorder - file 20160527_9749b67447774729be81d7381a1f97a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a96c2773d0f8c1b20de83bf7d22e2fc07a0807a1826ed9859a39c61f311abfa2"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aYJIxDnJR5X.length;i++)if(i%2==0)x.push(aYJIxDnJR5X[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}