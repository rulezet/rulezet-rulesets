rule sig_20160314_d21494443eba6180a9362684ed9435a4 {
  meta:
    description = "datamaliciousorder - file 20160314_d21494443eba6180a9362684ed9435a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58dd7c2d2392111dce0eb6daef34aa381be6dea931fb80a535c21545ac1728c6"

  strings:
    $s1 = "gxPE.open(ZLlojMklQQA, OZdxprZu + qNju + JPAsWTFHi + BoBmmhFXnbSzd + wSJjP + iopCnNBiLaHUyW + fMbZjNgWJM + CIDDZaIZTzqE + ZfuTGA" ascii
    $s2 = "while (gxPE.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = " + DrCHNOU + qpPHvltbUa + eikKAtXiOmlktiV + WTfrcIPjHt + zLKwOhioOzn + RuysEflgiKJNQ + hUEqqrPk + aZzCRCYBprL + TQctraLbB, false" ascii
    $s4 = "function FWTj(n)" fullword ascii
    $s5 = "return rzlWojuHrrwG + bas + GCAGmTQbgCjq + dHLvtIBFdGWE + ubzra + oOeRuD + WbsT" fullword ascii
    $s6 = "function LVaIdMIHReEtsH(fname)" fullword ascii
    $s7 = "var ifRWJmWRwvnbqE = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}