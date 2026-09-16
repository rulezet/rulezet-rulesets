rule sig_20160321_da1b606f3d04748fd51cd28ddddbfcd7 {
  meta:
    description = "datamaliciousorder - file 20160321_da1b606f3d04748fd51cd28ddddbfcd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96163945b1af383ec11add057fa44040f4de6ca401de92b147e5f785d3a787eb"

  strings:
    $s1  = "return WScript.CreateObject(eTsdy);" fullword ascii
    $s2  = "return ZIAjwKS[0] + ZIAjwKS[2] + ZIAjwKS[4] + \".F\" + ZIAjwKS[7] + ZIAjwKS[9] + ZIAjwKS[12] + ZIAjwKS[14];" fullword ascii
    $s3  = "var Qu = true  , YOen = ydf[7] + ydf[9] + ydf[11];" fullword ascii
    $s4  = "var ZIAjwKS = lTWTU(UnvIVFBcgg+\" \"+\"System nd JxqEN Obj gzbeuM ect rJEGjxI ITIxe\", \" \");" fullword ascii
    $s5  = "var ydf = (\"2.XMLHTTP sziMxQj HfXQi XML ream St HfUelNpl AD NSFTseD O mQPe D\").split(\" \");" fullword ascii
    $s6  = "Wpkqm.open(AyCNx,lhYBI,false);" fullword ascii
    $s7  = "function XcoA(Wpkqm,lhYBI,AyCNx) {" fullword ascii
    $s8  = "function yDAjKUqT(UOSj) {" fullword ascii
    $s9  = "return rCg.size;" fullword ascii
    $s10 = "function BvpEAWQkg(VSNBj) {" fullword ascii
    $s11 = "if(w>=K.length) {break;}" fullword ascii
    $s12 = "function JaUeVKUnW(GNVHWgzBqKO) {" fullword ascii
    $s13 = "EbJ = w; break; " fullword ascii
    $s14 = "function oYHb(aSNdM) {" fullword ascii
    $s15 = "return fmeBHX.position=692-692;" fullword ascii
    $s16 = "return CSuW.ExpandEnvironmentStrings(BGMkT);" fullword ascii
    $s17 = "return zEwhA.status;" fullword ascii
    $s18 = "return lfHR[cbFNhD[0]];" fullword ascii
    $s19 = "function RymyIyq(lfHR) {" fullword ascii
    $s20 = "function suLQC(fmeBHX) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}