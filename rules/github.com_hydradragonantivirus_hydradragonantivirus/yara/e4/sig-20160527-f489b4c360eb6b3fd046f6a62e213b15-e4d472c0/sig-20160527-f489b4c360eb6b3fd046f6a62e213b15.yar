rule sig_20160527_f489b4c360eb6b3fd046f6a62e213b15 {
  meta:
    description = "datamaliciousorder - file 20160527_f489b4c360eb6b3fd046f6a62e213b15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f1620c57a7eda787ef714a9bddfcec79276dfc1a07c4bd52b6911a1632807f1"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aF3bnhPl.length;i++)if(i%2==0)x.push(aF3bnhPl[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}