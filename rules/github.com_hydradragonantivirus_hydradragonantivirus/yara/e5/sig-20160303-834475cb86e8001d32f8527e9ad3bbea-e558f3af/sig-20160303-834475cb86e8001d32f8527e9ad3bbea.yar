rule sig_20160303_834475cb86e8001d32f8527e9ad3bbea {
  meta:
    description = "datamaliciousorder - file 20160303_834475cb86e8001d32f8527e9ad3bbea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "398d3895172866f8814dae5f281fb8d7cff4b2b052ff4e65fe0de4278ed72af3"

  strings:
    $s1  = "var bV = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(DKLUu);" fullword ascii
    $s3  = "var eEp = (Klo + \"TTP\" + \" MpkuzHW vUeJD XML ream St aIpqXXOY AD IqLNwhe OD\").split(\" \");" fullword ascii
    $s4  = "var HA = true  , qGmm = eEp[7] + \"\" + eEp[9];" fullword ascii
    $s5  = "return \"Sc\" + \"r\" + AufZyzF + \".F\" + EMuwNQgovf + DPtHM + \"Obj\" + \"ect\";" fullword ascii
    $s6  = "var dxb = WHuN(qGmm + \"B.\" + eEp[5]+(982418, eEp[4]));" fullword ascii
    $s7  = "Pkpoy.open(OuXkJ,vTxeD,false);" fullword ascii
    $s8  = "var Qu = WHuN(\"MS\"+eEp[3]+(589443, eEp[0]));" fullword ascii
    $s9  = "return HGzjC.status;" fullword ascii
    $s10 = "if(G>=i.length) {break;}" fullword ascii
    $s11 = "if (xjCzh == 977-777){return true;} else {return false;}" fullword ascii
    $s12 = "if (((new Date())>0,7673814888)) {" fullword ascii
    $s13 = "function CMCs(BfWEA,TgulE) {" fullword ascii
    $s14 = "function fFDjHuZvM(HcRzz,hsGsk,elTVC) {" fullword ascii
    $s15 = "return new ActiveXObject(wuLRIG);" fullword ascii
    $s16 = "function dRnt(Pkpoy,vTxeD,OuXkJ) {" fullword ascii
    $s17 = "function CsSf(epcRc) {" fullword ascii
    $s18 = "return Dj.ExpandEnvironmentStrings(bV);" fullword ascii
    $s19 = "function UPIf(JEvET) {" fullword ascii
    $s20 = "return SpSPz;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}