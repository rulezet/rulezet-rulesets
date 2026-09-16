rule sig_20160523_a178b3a56b88f209426a3fdebab0b351 {
  meta:
    description = "datamaliciousorder - file 20160523_a178b3a56b88f209426a3fdebab0b351.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76f15ef59c75e3e1ffbf37c55e24fe23c1d203af7baeacfad659951e99cf98c4"

  strings:
    $s1  = "function pxuVhutSUE() {return/*UULiZPdseUAPjHbpHmFGmMxqmOJKvZAuAnbbllGrwKaakORUHgkTslJLcnnxoeWGksnPMQISumMjfQnHluvflHNKTluuZpaaZ" ascii
    $s2  = "function BlDEODjMyG(aXEDJypH,yLroXmNPdIEK) {aXEDJypH.Run(yLroXmNPdIEK, 0x1, 0x0);}" fullword ascii
    $s3  = "function RVFxDwpq(XmQVa) {var DLjDSPTG=FRUpxfQqfHA[13];for(var QbgMm=0;QbgMm<XmQVa;QbgMm++){poTUJ+=DLjDSPTG.charAt(Math.floor(Ma" ascii
    $s4  = "function RVFxDwpq(XmQVa) {var DLjDSPTG=FRUpxfQqfHA[13];for(var QbgMm=0;QbgMm<XmQVa;QbgMm++){poTUJ+=DLjDSPTG.charAt(Math.floor(Ma" ascii
    $s5  = "function KZOpXw(WREnha){return WREnha.ExpandEnvironmentStrings(FRUpxfQqfHA[9])}" fullword ascii
    $s6  = "function mPGUCJP(KDUC,JomzE) {KDUC.write(JomzE);}" fullword ascii
    $s7  = "function hUpbjEBJ(tShAHgYwL) {tShAHgYwL.type=1;}" fullword ascii
    $s8  = "th.random()*DLjDSPTG.length));}return poTUJ;}" fullword ascii
    $s9  = "function oHrw(DEwiLO,gTNMCuS){mSpK = FRUpxfQqfHA[10].split(FRUpxfQqfHA[11]);gTNMCuS.open(mSpK[0]+mSpK[2]+mSpK[3], DEwiLO, false)" ascii
    $s10 = "function jWYmVguYzjNKC() {pxuVhutSUE().Sleep(2518869-295);}" fullword ascii
    $s11 = "function KlFz(HqKlJE) {HqKlJE.open();}" fullword ascii
    $s12 = "function duTBd(qxrHQroI,bwqVep,BzgGJPwMh){ajRkf=qxrHQroI.split(BzgGJPwMh);RmRHcbf = FRUpxfQqfHA[12];for(mtbEjVtF=0;mtbEjVtF<bwqV" ascii
    $s13 = "function eFhwalx() {var sOXr=100000;var fGlFsJ = 100;return fZmxQPP()*(sOXr-fGlFsJ)+fGlFsJ;}" fullword ascii
    $s14 = "function duTBd(qxrHQroI,bwqVep,BzgGJPwMh){ajRkf=qxrHQroI.split(BzgGJPwMh);RmRHcbf = FRUpxfQqfHA[12];for(mtbEjVtF=0;mtbEjVtF<bwqV" ascii
    $s15 = "function mfVc(rIDrYSp,DhEltzK) {rIDrYSp.saveToFile(DhEltzK, 2);}" fullword ascii
    $s16 = "function GFItLyA(fRFvs) {fRFvs.close();}" fullword ascii
    $s17 = "if(Vgzj>GGfFQ.length) break;" fullword ascii
    $s18 = "function pxuVhutSUE() {return/*UULiZPdseUAPjHbpHmFGmMxqmOJKvZAuAnbbllGrwKaakORUHgkTslJLcnnxoeWGksnPMQISumMjfQnHluvflHNKTluuZpaaZ" ascii
    $s19 = "function BBVCp(mIQerimS,LXlLk,AKdRMHTvnn){KlFz(mIQerimS);hUpbjEBJ(mIQerimS);mPGUCJP(mIQerimS,LXlLk);wfkYSWReX(mIQerimS);mfVc(mIQ" ascii
    $s20 = "function oHrw(DEwiLO,gTNMCuS){mSpK = FRUpxfQqfHA[10].split(FRUpxfQqfHA[11]);gTNMCuS.open(mSpK[0]+mSpK[2]+mSpK[3], DEwiLO, false)" ascii

  condition:
    uint16(0) == 0x1e27 and
    8 of them
}