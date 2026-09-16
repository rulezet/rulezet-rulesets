rule sig_20160527_564afbcaefaa167073426a18ba5d0b6c {
  meta:
    description = "datamaliciousorder - file 20160527_564afbcaefaa167073426a18ba5d0b6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "095f376757a80578fee3c85317002671c6edccced61352b81ec73d7fab1e0e2d"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<az1IJUF.length;i++)if(i%2==0)x.push(az1IJUF[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}