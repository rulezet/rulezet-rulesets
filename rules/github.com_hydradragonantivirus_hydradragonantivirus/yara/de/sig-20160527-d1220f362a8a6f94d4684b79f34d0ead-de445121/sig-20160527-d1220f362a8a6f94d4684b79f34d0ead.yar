rule sig_20160527_d1220f362a8a6f94d4684b79f34d0ead {
  meta:
    description = "datamaliciousorder - file 20160527_d1220f362a8a6f94d4684b79f34d0ead.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f7bd2d959895df97c373bc1b80601b73b3302c073c24c969050c609c66976af"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a945nCe0Jrs.length;i++)if(i%2==0)x.push(a945nCe0Jrs[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}