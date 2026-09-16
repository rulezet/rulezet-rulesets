rule sig_20160527_7c19a8bab6fc16190ddaa879ac4f9ec0 {
  meta:
    description = "datamaliciousorder - file 20160527_7c19a8bab6fc16190ddaa879ac4f9ec0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1498bfc715448655be28049b127064b9c492ad3db3077c667380adf5ad7208e3"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<abAYM9I.length;i++)if(i%2==0)x.push(abAYM9I[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}