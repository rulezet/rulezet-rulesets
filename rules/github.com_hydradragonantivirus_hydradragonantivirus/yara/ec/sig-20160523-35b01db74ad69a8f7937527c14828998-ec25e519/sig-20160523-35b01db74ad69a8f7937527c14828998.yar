rule sig_20160523_35b01db74ad69a8f7937527c14828998 {
  meta:
    description = "datamaliciousorder - file 20160523_35b01db74ad69a8f7937527c14828998.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96e20d7b25eda9c24938d023bbbcb31f0304b6c1520af78831c739f79840b540"

  strings:
    $s1  = "function OiWMkOWVzZ(hSLcvDzH,dyTZYEzRxrwt) {hSLcvDzH.Run(dyTZYEzRxrwt, 0x1, 0x0);}" fullword ascii
    $s2  = "function UsHnDuEk(tBenc) {var hGAPchBs=zgKdhBEBxusegiaByVMg[13];for(var EhwVH=0;EhwVH<tBenc;EhwVH++){DQkAU+=hGAPchBs.charAt(Math" ascii
    $s3  = "function UsHnDuEk(tBenc) {var hGAPchBs=zgKdhBEBxusegiaByVMg[13];for(var EhwVH=0;EhwVH<tBenc;EhwVH++){DQkAU+=hGAPchBs.charAt(Math" ascii
    $s4  = "function seoDJrT(){return Math.random();}" fullword ascii
    $s5  = "function wEYtUiSz(HdTENyTFT) {HdTENyTFT.type=1;}" fullword ascii
    $s6  = "function flbcjNR(TxPy,yekWv) {TxPy.write(yekWv);}" fullword ascii
    $s7  = "lVYx<LGJUib.length;zliKlVYx++) {pelwXCK+=QjaXs[LGJUib[zliKlVYx]];}return pelwXCK.substring(3,pelwXCK.length);}" fullword ascii
    $s8  = "function gomKEtI(sEwOT) {sEwOT.close();}" fullword ascii
    $s9  = "function igwaE(JvvlpJQG,LGJUib,ZIqokZwlo){QjaXs=JvvlpJQG.split(ZIqokZwlo);pelwXCK = zgKdhBEBxusegiaByVMg[12];for(zliKlVYx=0;zliK" ascii
    $s10 = "if(jpuJ>BuvVX.length) break;" fullword ascii
    $s11 = "function igwaE(JvvlpJQG,LGJUib,ZIqokZwlo){QjaXs=JvvlpJQG.split(ZIqokZwlo);pelwXCK = zgKdhBEBxusegiaByVMg[12];for(zliKlVYx=0;zliK" ascii
    $s12 = "function tlBKy(BgjjxOnn,rYbWb,HeTSpBrJUX){pGzU(BgjjxOnn);wEYtUiSz(BgjjxOnn);flbcjNR(BgjjxOnn,rYbWb);RqIPVZHkc(BgjjxOnn);iiHz(Bgj" ascii
    $s13 = "function RqIPVZHkc(DrNwTL) {var bPnngtEVHS=[];DrNwTL.position=bPnngtEVHS.length*(2576152-370);}" fullword ascii
    $s14 = "function pGzU(PIIDVM) {PIIDVM.open();}" fullword ascii
    $s15 = "function cRTw(jjmEAb,xzlnyMb){jNwj = zgKdhBEBxusegiaByVMg[10].split(zgKdhBEBxusegiaByVMg[11]);xzlnyMb.open(jNwj[0]+jNwj[2]+jNwj[" ascii
    $s16 = "function tlBKy(BgjjxOnn,rYbWb,HeTSpBrJUX){pGzU(BgjjxOnn);wEYtUiSz(BgjjxOnn);flbcjNR(BgjjxOnn,rYbWb);RqIPVZHkc(BgjjxOnn);iiHz(Bgj" ascii
    $s17 = "3], jjmEAb, false);xzlnyMb.send();}" fullword ascii
    $s18 = "function cRTw(jjmEAb,xzlnyMb){jNwj = zgKdhBEBxusegiaByVMg[10].split(zgKdhBEBxusegiaByVMg[11]);xzlnyMb.open(jNwj[0]+jNwj[2]+jNwj[" ascii
    $s19 = ".floor(Math.random()*hGAPchBs.length));}return DQkAU;}" fullword ascii
    $s20 = "function LJbGeZb() {var aDDO=100000;var dOgFpQ = 100;return seoDJrT()*(aDDO-dOgFpQ)+dOgFpQ;}" fullword ascii

  condition:
    uint16(0) == 0x0c27 and
    8 of them
}