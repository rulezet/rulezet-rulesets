rule sig_20160315_cfc0e61679d7802dadc55dae71bc1ece {
  meta:
    description = "datamaliciousorder - file 20160315_cfc0e61679d7802dadc55dae71bc1ece.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1419b77c29aa7a0557258cea0dbc0d33de724bd452333502c9ffe73693052957"

  strings:
    $s1 = "while (lXUxbqACU.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "function EbhTXbkY(pUS){WshShell[plmFU](pUS, 0, 0);}" fullword ascii
    $s3 = "function WyfQoWdtgVjgUEt(n){return GsGxtifOMVM + tlkPkjalirtOrGP + AkswmdAqvRgoAwc + uepRC + MnvCWAGWN + uxjQvYKAiTaAkPT + FiUmf" ascii
    $s4 = "function WyfQoWdtgVjgUEt(n){return GsGxtifOMVM + tlkPkjalirtOrGP + AkswmdAqvRgoAwc + uepRC + MnvCWAGWN + uxjQvYKAiTaAkPT + FiUmf" ascii
    $s5 = "var xxPNS = new Date();" fullword ascii
    $s6 = "KiyCqM, false);" fullword ascii
    $s7 = "lXUxbqACU[eGQxjb + rknWdJ](yaMXcDwSRmDPD, Urt + NifFxbnb + hKbTVQz + tGoGbCJHAEHhs + CIHcAHoyhNBt + dVYdDUOv + reoIFwg + AZDjnOM" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}