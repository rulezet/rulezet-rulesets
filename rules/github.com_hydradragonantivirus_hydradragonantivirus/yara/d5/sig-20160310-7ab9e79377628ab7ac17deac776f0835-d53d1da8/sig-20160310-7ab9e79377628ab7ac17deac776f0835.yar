rule sig_20160310_7ab9e79377628ab7ac17deac776f0835 {
  meta:
    description = "datamaliciousorder - file 20160310_7ab9e79377628ab7ac17deac776f0835.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7f77d5e3a91d5732f46a37c6b776be2c3e3c7be6e5384930d292251ff328c5e"

  strings:
    $s1  = "var FP = true  , konN = Ayx[7] + Ayx[9] + Ayx[11];" fullword ascii
    $s2  = "return AkltXtB[0] + AkltXtB[2] + AkltXtB[4] + \".F\" + AkltXtB[7] + AkltXtB[9] + AkltXtB[12] + AkltXtB[14];" fullword ascii
    $s3  = "var Ayx = (\"2.XMLHTTP dbYjpDS qFsTH XML ream St bavEeqCm AD ebHggrk O oVdc D\").split(\" \");" fullword ascii
    $s4  = "VotUc.open(vivGs,wzNVk,false);" fullword ascii
    $s5  = "var AkltXtB = \"Sc JtozYlP r euYAnPybP ipting mcJArPA RXE ile BvimecWEggBMsf System If kXUXz Obj efIFhu ect CmBvAIw\".split(\" " ascii
    $s6  = "function nVmQ(WUgQS) {" fullword ascii
    $s7  = "if (d >= fQjRF.length) {break;}" fullword ascii
    $s8  = "function cOnB(EAnJW,sVwNT) {" fullword ascii
    $s9  = "function iiSf(MruME) {" fullword ascii
    $s10 = "function AKUNR(aFazDl) {" fullword ascii
    $s11 = "return njtW.responseBody;" fullword ascii
    $s12 = "function nVpolrR(njtW) {" fullword ascii
    $s13 = "function dBjjLWmUq(PIRuY,ImxQU,aDgqQ,lpCZ) {" fullword ascii
    $s14 = "function LiqzieDn() {" fullword ascii
    $s15 = "return new ActiveXObject(aFazDl);" fullword ascii
    $s16 = "return CFceeDv(cR,AsCYG[554-548]+AsCYG[111-104]+AsCYG[520-512]);" fullword ascii
    $s17 = "function CFceeDv(gMTm,jGyXA) {" fullword ascii
    $s18 = "return ybkYGUA" fullword ascii
    $s19 = "function pZjEJsDjg(lSnfYXCerfq) {" fullword ascii
    $s20 = "function itof(fQjRF) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}