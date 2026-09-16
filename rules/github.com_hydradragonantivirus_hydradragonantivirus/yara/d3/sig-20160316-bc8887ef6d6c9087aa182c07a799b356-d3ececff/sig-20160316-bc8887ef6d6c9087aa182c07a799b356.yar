rule sig_20160316_bc8887ef6d6c9087aa182c07a799b356 {
  meta:
    description = "datamaliciousorder - file 20160316_bc8887ef6d6c9087aa182c07a799b356.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d3be06486c08474f86295e4865a9e982ec30c09563da427f664a44c82de84af"

  strings:
    $s1 = "while (gqpifKvn[GxbvRU + GFXFVNEBu + nThJlLgX + gCLLhmartROO + KCewJImBQLKZ] < 4 ) {WScript[eRSKHj + wJr + xapPyqsvhwrd](1000)};" ascii
    $s2 = "function fKuPMBQePQRE(n){return ZrmXMqIw + wsHbjbnlYQReq + deFaiyoWDb + cCVnuBmlSw + cJDPIzKscX + ZtCv;}" fullword ascii
    $s3 = "+ TsacYfCi + vlCXWJhcItcC + jcJHJZAkjQS + THTrfnealR + fagIJEJFCz, false);" fullword ascii
    $s4 = "function IwLCQwXJGxOFsU(uLvaLcN){zNadz[ERgaDTXt + KApAv + WOf](uLvaLcN, 0, 0);}" fullword ascii
    $s5 = "gqpifKvn[TRKHrHBSz + XCtBnNZtRXhbjK](JhPNNdUWpzh, qBRZagj + CyXWkeNzUL + xYipZiQz + MeT0 + nMIa + iwVhDuABR + AnZg + SqmSMgyBRk " ascii
    $s6 = "var ymYlhumXgPxULep = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}