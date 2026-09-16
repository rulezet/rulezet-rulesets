rule sig_20160527_ebb1dfc6503c70bb02b3b70414b71cc5 {
  meta:
    description = "datamaliciousorder - file 20160527_ebb1dfc6503c70bb02b3b70414b71cc5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8468d7ade14610a9651044eceab210c54c5c2e60c69104d4112e26427f8b2d93"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<abPqLe.length;i++)if(i%2==0)x.push(abPqLe[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}