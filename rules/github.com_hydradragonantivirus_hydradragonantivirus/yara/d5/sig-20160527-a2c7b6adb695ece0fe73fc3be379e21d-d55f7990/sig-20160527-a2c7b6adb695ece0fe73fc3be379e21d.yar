rule sig_20160527_a2c7b6adb695ece0fe73fc3be379e21d {
  meta:
    description = "datamaliciousorder - file 20160527_a2c7b6adb695ece0fe73fc3be379e21d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7754e93f8104f51b6e9d55d5e2ea2a6fb937669bf87a73f22036451961501c9a"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aM5sweIYt.length;i++)if(i%2==0)x.push(aM5sweIYt[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}