rule sig_20160523_8183c6fd32acb41363b4e6fcd5ccc3b8 {
  meta:
    description = "datamaliciousorder - file 20160523_8183c6fd32acb41363b4e6fcd5ccc3b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0649f3c28f2ac096d42888ca2417eae02e29d41aa5b78c4c627bdb50bdc11291"

  strings:
    $s1  = "function bCttODal(JzxYK) {var UcpyyDjp=DiPYJ[13];for(var PiBdd=0;PiBdd<JzxYK;PiBdd++){prpXV+=UcpyyDjp.charAt(Math.floor(Math.ran" ascii
    $s2  = "function PMfNgGenqP(RFiSlYfd,YNOwdUvcvvSB) {RFiSlYfd.Run(YNOwdUvcvvSB, 0x1, 0x0);}" fullword ascii
    $s3  = "function SkUdhEoueA() {return/*CBClUysiROUOHdwlLBVySAsWeZyfAnLcfEwKPlgBQoIBLfEdPEYSOdneWizuWllAuXSnzDpZGiPFqOgUEIETXtoVbdTIfKEiT" ascii
    $s4  = "function bCttODal(JzxYK) {var UcpyyDjp=DiPYJ[13];for(var PiBdd=0;PiBdd<JzxYK;PiBdd++){prpXV+=UcpyyDjp.charAt(Math.floor(Math.ran" ascii
    $s5  = "function UnVs(zDRipq,lHuidvA){EtMt = DiPYJ[10].split(DiPYJ[11]);lHuidvA.open(EtMt[0]+EtMt[2]+EtMt[3], zDRipq, false);lHuidvA.sen" ascii
    $s6  = "function igbwa(PIKWQjrV,iKhsBx,XEdKBuKNW){aHORX=PIKWQjrV.split(XEdKBuKNW);YFeIIJG = DiPYJ[12];for(QXRUxvHn=0;QXRUxvHn<iKhsBx.len" ascii
    $s7  = "function bZTDbFRrs(TgTGht) {var yJESRzrtqq=[];TgTGht.position=yJESRzrtqq.length*(2675355-694);}" fullword ascii
    $s8  = "if(nkFw>oLzkQ.length) break;" fullword ascii
    $s9  = "function igbwa(PIKWQjrV,iKhsBx,XEdKBuKNW){aHORX=PIKWQjrV.split(XEdKBuKNW);YFeIIJG = DiPYJ[12];for(QXRUxvHn=0;QXRUxvHn<iKhsBx.len" ascii
    $s10 = "function SkUdhEoueA() {return/*CBClUysiROUOHdwlLBVySAsWeZyfAnLcfEwKPlgBQoIBLfEdPEYSOdneWizuWllAuXSnzDpZGiPFqOgUEIETXtoVbdTIfKEiT" ascii
    $s11 = "function yKDOeTg(XZNP,xqeEl) {XZNP.write(xqeEl);}" fullword ascii
    $s12 = "function bIiQOA(ZqRSzu){return ZqRSzu.ExpandEnvironmentStrings(DiPYJ[9])}" fullword ascii
    $s13 = "function jemoXBC(){return Math.random();}" fullword ascii
    $s14 = "function WXnT(brvQDk) {brvQDk.open();}" fullword ascii
    $s15 = "gth;QXRUxvHn++) {YFeIIJG+=aHORX[iKhsBx[QXRUxvHn]];}return YFeIIJG.substring(3,YFeIIJG.length);}" fullword ascii
    $s16 = "function HDDejTxu(rKbaQbqFg) {rKbaQbqFg.type=1;}" fullword ascii
    $s17 = "function nNBr(quZsmPD,nKMfAGZ) {quZsmPD.saveToFile(nKMfAGZ, 2);}" fullword ascii
    $s18 = "function QUhnf(RTBbrgah,iMzbZ,oMjJjCeFNh){WXnT(RTBbrgah);HDDejTxu(RTBbrgah);yKDOeTg(RTBbrgah,iMzbZ);bZTDbFRrs(RTBbrgah);nNBr(RTB" ascii
    $s19 = "function QUhnf(RTBbrgah,iMzbZ,oMjJjCeFNh){WXnT(RTBbrgah);HDDejTxu(RTBbrgah);yKDOeTg(RTBbrgah,iMzbZ);bZTDbFRrs(RTBbrgah);nNBr(RTB" ascii
    $s20 = "function owHqXGO(BXpUq) {BXpUq.close();}" fullword ascii

  condition:
    uint16(0) == 0x0827 and
    8 of them
}