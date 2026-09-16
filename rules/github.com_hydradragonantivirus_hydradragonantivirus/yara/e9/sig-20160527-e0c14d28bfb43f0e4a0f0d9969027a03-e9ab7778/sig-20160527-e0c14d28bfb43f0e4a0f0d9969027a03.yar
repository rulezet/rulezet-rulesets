rule sig_20160527_e0c14d28bfb43f0e4a0f0d9969027a03 {
  meta:
    description = "datamaliciousorder - file 20160527_e0c14d28bfb43f0e4a0f0d9969027a03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83aac900c6d908c5c2271a8cfdb7a4ed263a4c2f390008ae523a9af804bfc19e"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aJDZTdf9Pqq.length;i++)if(i%2==0)x.push(aJDZTdf9Pqq[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}