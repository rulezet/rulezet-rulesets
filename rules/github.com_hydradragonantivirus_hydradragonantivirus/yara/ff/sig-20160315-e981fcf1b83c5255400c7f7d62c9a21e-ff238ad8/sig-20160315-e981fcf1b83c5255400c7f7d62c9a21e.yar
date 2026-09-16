rule sig_20160315_e981fcf1b83c5255400c7f7d62c9a21e {
  meta:
    description = "datamaliciousorder - file 20160315_e981fcf1b83c5255400c7f7d62c9a21e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b49831ae35932297b2293ae26392959639f80f03d679399c40abc6b56e7413b"

  strings:
    $s1 = "function QsFhuaxYzRxXc(dZvzIOFUxK){WshShell[WJHItlqh + bNsIGHHC](dZvzIOFUxK, 0, 0);}" fullword ascii
    $s2 = "while (DppgGRe.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "NrAtHhZO + UbeclBcBJJRj + KdEwCX + PKaldwNRgvZYBbQ + ldFSPtkq + UUJTn + zFlioxBQEaeILtH + VFVmFYFSpdxa + ItJkDeoqiGIGh, false);" fullword ascii
    $s4 = "function qEYsZDlQYaiur(n){return vGrfZxkVGlXIsYi + yMIilcRfsXB + oKMjTyteRi + xcTciDBXuSGiJn + vmLRrIJezTqMKzp + afQyhRmrHiCWcth" ascii
    $s5 = "function qEYsZDlQYaiur(n){return vGrfZxkVGlXIsYi + yMIilcRfsXB + oKMjTyteRi + xcTciDBXuSGiJn + vmLRrIJezTqMKzp + afQyhRmrHiCWcth" ascii
    $s6 = "DppgGRe[ckqhih + KHtjkUF](bVcM + RmuTxLSz + cAxEhHikLxvck, AxiHfxLeaDXPz + QoBM + zpQMZsYFw + GyJOdSlB + PDgh + lnIoIwYROq + tVy" ascii
    $s7 = "var jsOyRsXq = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}