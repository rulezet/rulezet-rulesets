rule sig_20160530_8d5eada60bcf4b952089d82eddea58ce {
  meta:
    description = "datamaliciousorder - file 20160530_8d5eada60bcf4b952089d82eddea58ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d257e72364e270adfc30a59c314c2a0a6e3a62ec5e149b2d186e487f6205364"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a8j6zW6bv8I.length;i++)if(i%2==0)x.push(a8j6zW6bv8I[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}