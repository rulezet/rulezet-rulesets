rule sig_20160527_7f1ef3eb239ec4091bfa3ac50098646f {
  meta:
    description = "datamaliciousorder - file 20160527_7f1ef3eb239ec4091bfa3ac50098646f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9ded76edb4659c7f8412e62ec142bd3fbc61efe694ad860e968fc5929bcf10d"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a47jJ9P0.length;i++)if(i%2==0)x.push(a47jJ9P0[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}