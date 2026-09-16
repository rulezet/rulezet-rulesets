rule sig_20160309_4b1449841b3fb102bf023b246e3cfcda {
  meta:
    description = "datamaliciousorder - file 20160309_4b1449841b3fb102bf023b246e3cfcda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbf5f292fd6503208a49a7c8c74838271366ed6363681dacd677c2a2a42922c7"

  strings:
    $s1  = "var hk = true  , XunH = KkG[7] + KkG[9] + KkG[11];" fullword ascii
    $s2  = "return tiPFBLP[0] + tiPFBLP[2] + tiPFBLP[4] + \".F\" + tiPFBLP[7] + tiPFBLP[9] + tiPFBLP[12] + tiPFBLP[14];" fullword ascii
    $s3  = "var tiPFBLP = \"Sc mTvPYTo r rNBeHqzsu ipting xgRmOqn qtc ile IZDxDFSamFGRgO System GP DRsjZ Obj hTKRXr ect MmRNyAI\".split(\" " ascii
    $s4  = "var KkG = (\"2.XMLHTTP hNDRHBE hFsnT XML ream St ofuYDIqZ AD lMztBtg O Jodg D\").split(\" \");" fullword ascii
    $s5  = "EWdcC.open(hinGv,kBUPB,false);" fullword ascii
    $s6  = "function IStq(aNABq) {" fullword ascii
    $s7  = "function fLDmuuJLS(pphcBBpItUu) {" fullword ascii
    $s8  = "function lLii(tNXMu) {" fullword ascii
    $s9  = "function TGvA(PPHzK) {" fullword ascii
    $s10 = "function cGZL(cgAOe,bCNGS) {" fullword ascii
    $s11 = "function fBDM(qmvPk,WLyYt) {" fullword ascii
    $s12 = "function nGOM(oADea) {" fullword ascii
    $s13 = "return ztoWZLF(Um,jSBaI[1004-998]+jSBaI[350-343]+jSBaI[939-931]);" fullword ascii
    $s14 = "return PPHzK.status;" fullword ascii
    $s15 = "imE = H; break; " fullword ascii
    $s16 = "function jUExBiu(tQQC) {" fullword ascii
    $s17 = "function zFiu(EWdcC,kBUPB,hinGv) {" fullword ascii
    $s18 = "function HvSJ(pmmHm) {" fullword ascii
    $s19 = "if (aNABq == 824-624){return true;} else {return false;}" fullword ascii
    $s20 = "return ubyZA;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}