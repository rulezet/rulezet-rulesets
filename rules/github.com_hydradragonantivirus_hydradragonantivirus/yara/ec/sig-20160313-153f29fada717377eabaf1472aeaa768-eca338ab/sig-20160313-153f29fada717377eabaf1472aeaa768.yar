rule sig_20160313_153f29fada717377eabaf1472aeaa768 {
  meta:
    description = "datamaliciousorder - file 20160313_153f29fada717377eabaf1472aeaa768.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a784509c0825d35bc98c8a99a3f9f76833a7fe7ccb9e52176d602dc5691b656"

  strings:
    $s1  = "var oH = true  , HhZs = ksG[7] + ksG[9] + ksG[11];" fullword ascii
    $s2  = "return nhEmdNm[0] + nhEmdNm[2] + nhEmdNm[4] + \".F\" + nhEmdNm[7] + nhEmdNm[9] + nhEmdNm[12] + nhEmdNm[14];" fullword ascii
    $s3  = "var nhEmdNm = \"Sc KiIHatw r COAbOKMxA ipting pgygUuY kGw ile fmyaShPysoFcPY System Jy hCkur Obj AJFHgX ect luYfVPG\".split(\" " ascii
    $s4  = "DrdWh.open(iAVrX,CxbFY,false);" fullword ascii
    $s5  = "var ksG = (\"2.XMLHTTP LMJIgvu EgoIS XML ream St mQpIrQnE AD iLxPJfH O ZEMb D\").split(\" \");" fullword ascii
    $s6  = "gSO = H; break; " fullword ascii
    $s7  = "return oTVhjab(SU,kuTvL[355-349]+kuTvL[550-543]+kuTvL[683-675]);" fullword ascii
    $s8  = "function qtss(TqCOk) {" fullword ascii
    $s9  = "return WhDy.responseBody;" fullword ascii
    $s10 = "function ZKiyKkxi() {" fullword ascii
    $s11 = "function zYpq(MJMat,Ozhwe) {" fullword ascii
    $s12 = "return fDwcqm.position=225-225;" fullword ascii
    $s13 = "if (o >= FsePT.length) {break;}" fullword ascii
    $s14 = "if(H>=v.length) {break;}" fullword ascii
    $s15 = "function wDDCJMBB(gno) {" fullword ascii
    $s16 = "function dvSF(hCEit) {" fullword ascii
    $s17 = "function SnQSl(fDwcqm) {" fullword ascii
    $s18 = "function zhst(ZddOI) {" fullword ascii
    $s19 = "return TqCOk.status;" fullword ascii
    $s20 = "function Ycfx(TGQkC) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}