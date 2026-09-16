rule sig_20160527_7010c97dcaa9c84549ef1bda2ea75602 {
  meta:
    description = "datamaliciousorder - file 20160527_7010c97dcaa9c84549ef1bda2ea75602.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3df614f55b0abf7e725f4f3956c47bdde7c3ffacac504160eb1835d811af887"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aHgkne6QzJb.length;i++)if(i%2==0)x.push(aHgkne6QzJb[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}