rule sig_20160404_d05ee04243c803b467102cdf7c0276eb {
  meta:
    description = "datamaliciousorder - file 20160404_d05ee04243c803b467102cdf7c0276eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "210c1cf9bb17aad15bdf782a4e15c654d27da652b94257a57d4139832771b00b"

  strings:
    $s1  = "var zV = true  , DgGX = XVK[7] + XVK[9] + XVK[11];" fullword ascii
    $s2  = "return tCRXSvC[0] + tCRXSvC[2] + tCRXSvC[4] + \".F\" + tCRXSvC[7] + tCRXSvC[9] + tCRXSvC[12] + tCRXSvC[14];" fullword ascii
    $s3  = "tOBs.open(PaDyM,BVcen,false);" fullword ascii
    $s4  = "function pAwnSRkTb(hidUV) {" fullword ascii
    $s5  = "var XVK = (\"2.XMLHTTP ENnHonH rCNXy XML ream St xfvNXixp AD kPZtfPS O yjPR D\").split(\" \");" fullword ascii
    $s6  = "function CojS(hzQEe) {" fullword ascii
    $s7  = "if(g>=m.length) {break;}" fullword ascii
    $s8  = "function DayDT(ABeKic) {" fullword ascii
    $s9  = "function GGQgy(rHLRSICZ,NKRS) {" fullword ascii
    $s10 = "function HcroJCm(ondI) {" fullword ascii
    $s11 = "function ILqK(gjqQG) {" fullword ascii
    $s12 = "return ZqK.split(IoNlW);" fullword ascii
    $s13 = "if (QSDYH > 182813-875){return true;} else {return false;}" fullword ascii
    $s14 = "if (v >= PxabM.length) {break;}" fullword ascii
    $s15 = "function AKXsZV(qzDLUzT) {" fullword ascii
    $s16 = "return sIuoR;" fullword ascii
    $s17 = "function MSwkm(ZqK,IoNlW) {" fullword ascii
    $s18 = "return \"hHigqcRFYVwSiv\";" fullword ascii
    $s19 = "function pLyerP(NoTX,DywaGh) {" fullword ascii
    $s20 = "function Vrue(gWuYd) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}