rule sig_20160527_1858af981312512f7d26dcf57d199b69 {
  meta:
    description = "datamaliciousorder - file 20160527_1858af981312512f7d26dcf57d199b69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c848f153908f12c55e500f80d3268270fea8659ed3deac666671e645776d0808"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<awL5YBh.length;i++)if(i%2==0)x.push(awL5YBh[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}