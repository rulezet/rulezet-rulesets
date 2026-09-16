rule sig_20160523_48389b3190903d055dd0cdf024bfb01b {
  meta:
    description = "datamaliciousorder - file 20160523_48389b3190903d055dd0cdf024bfb01b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fcd2e16acefacb08c5d9fcbaaacf0b2edc1ef53b2ec3d134a4f97b43c4973f8"

  strings:
    $s1  = "function qJbHpVOmOy() {return/*LHyMGrjeLvNZGayoJqzGQiSPyyJoyGQkEVSGJqLVbKAdLAgsWolsOcOoHPsyDbZcIPzCunVpbPoYWervtedEIkZyGMmbMLJZr" ascii
    $s2  = "function LJuuXzfu(jvTLX) {var VstIomOz=eztoM[13];for(var fvBmS=0;fvBmS<jvTLX;fvBmS++){Hjaci+=VstIomOz.charAt(Math.floor(Math.ran" ascii
    $s3  = "function YlkfagSHvN(LxoPCPUr,CRcfFhFZsPmN) {LxoPCPUr.Run(CRcfFhFZsPmN, 0x1, 0x0);}" fullword ascii
    $s4  = "function LJuuXzfu(jvTLX) {var VstIomOz=eztoM[13];for(var fvBmS=0;fvBmS<jvTLX;fvBmS++){Hjaci+=VstIomOz.charAt(Math.floor(Math.ran" ascii
    $s5  = "function qJbHpVOmOy() {return/*LHyMGrjeLvNZGayoJqzGQiSPyyJoyGQkEVSGJqLVbKAdLAgsWolsOcOoHPsyDbZcIPzCunVpbPoYWervtedEIkZyGMmbMLJZr" ascii
    $s6  = "function pQxtv(WYRiqvZi,dstHGI,aNOqofHjI){hYQck=WYRiqvZi.split(aNOqofHjI);ExrVdUw = eztoM[12];for(zbvFCgXf=0;zbvFCgXf<dstHGI.len" ascii
    $s7  = "function nmYT(ihxcCS,bmzyQWH){jyFH = eztoM[10].split(eztoM[11]);bmzyQWH.open(jyFH[0]+jyFH[2]+jyFH[3], ihxcCS, false);bmzyQWH.sen" ascii
    $s8  = "if(qTSE>vywyd.length) break;" fullword ascii
    $s9  = "function WOiuJk(tJDUyU){return tJDUyU.ExpandEnvironmentStrings(eztoM[9])}" fullword ascii
    $s10 = "gth;zbvFCgXf++) {ExrVdUw+=hYQck[dstHGI[zbvFCgXf]];}return ExrVdUw.substring(3,ExrVdUw.length);}" fullword ascii
    $s11 = "function puRZOkrJbBheW() {qJbHpVOmOy().Sleep(2327764-424);}" fullword ascii
    $s12 = "function siDbpOA() {var kRzX=100000;var qDFmXN = 100;return xbsjDFx()*(kRzX-qDFmXN)+qDFmXN;}" fullword ascii
    $s13 = "function nmYT(ihxcCS,bmzyQWH){jyFH = eztoM[10].split(eztoM[11]);bmzyQWH.open(jyFH[0]+jyFH[2]+jyFH[3], ihxcCS, false);bmzyQWH.sen" ascii
    $s14 = "function pQxtv(WYRiqvZi,dstHGI,aNOqofHjI){hYQck=WYRiqvZi.split(aNOqofHjI);ExrVdUw = eztoM[12];for(zbvFCgXf=0;zbvFCgXf<dstHGI.len" ascii
    $s15 = "function UQUQLNOU(ULpjZLPfp) {ULpjZLPfp.type=1;}" fullword ascii
    $s16 = "dom()*VstIomOz.length));}return Hjaci;}" fullword ascii
    $s17 = "function pWQd(urHeVDU,LzSYTsZ) {urHeVDU.saveToFile(LzSYTsZ, 2);}" fullword ascii
    $s18 = "function xbsjDFx(){return Math.random();}" fullword ascii
    $s19 = "function XQTb(mXBXCB) {mXBXCB.open();}" fullword ascii
    $s20 = "function kiMif(tJDUyU){return new ActiveXObject(tJDUyU);}" fullword ascii

  condition:
    uint16(0) == 0x0727 and
    8 of them
}