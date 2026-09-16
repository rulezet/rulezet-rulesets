rule sig_20160527_14b84979d306a2240d0dca855eb38206 {
  meta:
    description = "datamaliciousorder - file 20160527_14b84979d306a2240d0dca855eb38206.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bd1c90ed6d9df0867093b960f9546f8d3a5fc9f77bb42ba1bd4fdea9439455c"

  strings:
    $s1  = "function LCjLTGfS() {return WScript;}function pgHqxqeWBwHVV(){return aRiJGoyr.ExpandEnvironmentStrings(SFfRWj())}" fullword ascii
    $s2  = "function CxAErRRJZMs(aNvee,NYRGumaAjZHhrDha){return aNvee.charAt(NYRGumaAjZHhrDha);}" fullword ascii
    $s3  = "var aRiJGoyr=function(){return LCjLTGfS().CreateObject(OepfSGrLMdBEOOtE[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s4  = "function TTsKJVqjt(wEXbPazpFMXkp) {var OfrqNhZZPekKSur = clWPhWnbavj.join(OepfSGrLMdBEOOtE[6]);var FwCgnobGoNgycyqau, YYglJpHhYH" ascii
    $s5  = "function TAALumxIqKJsDTOHkXRI(OBPzn,RxwIOVf){return String.fromCharCode(OBPzn,RxwIOVf);}" fullword ascii
    $s6  = "function RmZERwXEde(){return FEKSfmA(OepfSGrLMdBEOOtE[10],[2,4,8,10],OepfSGrLMdBEOOtE[11]);}" fullword ascii
    $s7  = "var mpikfvx=function(){return new ActiveXObject(OepfSGrLMdBEOOtE[0]);}();" fullword ascii
    $s8  = "function FEKSfmA(gDNzkD,txEvoQdZyq,PpOnzOsBE){HpFOVtPNuw=gDNzkD.split(PpOnzOsBE);JfDlRKVS = OepfSGrLMdBEOOtE[14];for(hDYYMdxlnQ=" ascii
    $s9  = "function CQLJhAgDC(){return FEKSfmA(OepfSGrLMdBEOOtE[12],[0,3,6],OepfSGrLMdBEOOtE[13]);}" fullword ascii
    $s10 = "(vKhSscOhKoWubwBbO == 64) cmBUyqGjRlROxhX += TAALumxIqKJsDTOHkXRI(FwCgnobGoNgycyqau, YYglJpHhYHRipXLbaOx);else cmBUyqGjRlROxhX +" ascii
    $s11 = "th);return cmBUyqGjRlROxhX;}" fullword ascii
    $s12 = "function SFfRWj(){return FEKSfmA(OepfSGrLMdBEOOtE[8],[1,5,7],OepfSGrLMdBEOOtE[9]);}" fullword ascii
    $s13 = "0;hDYYMdxlnQ<txEvoQdZyq.length;hDYYMdxlnQ++) {JfDlRKVS+=HpFOVtPNuw[txEvoQdZyq[hDYYMdxlnQ]];}return JfDlRKVS.substring(3,JfDlRKVS" ascii
    $s14 = "function GUGJQJAdZaflZaQ(zApvAtP,LETjHaFHpBN,bvydTAPXCPkrLqcg){return String.fromCharCode(zApvAtP,LETjHaFHpBN,bvydTAPXCPkrLqcg);" ascii
    $s15 = "function RjKRkGEOPPe(ouUNhMigPlOF,zGdfDkDxlmLW) {var AYBKpyoCmgl=[OepfSGrLMdBEOOtE[15]];ouUNhMigPlOF[AYBKpyoCmgl[0]](zGdfDkDxlmL" ascii
    $s16 = "e(92)+OepfSGrLMdBEOOtE[4],true);" fullword ascii
    $s17 = "& 0xff;xymEXkHqhGdtNRxnt = wNBURXziIKOSrUbhxq & 0xff;if (QmTrmOJnzrBcjd == 64) cmBUyqGjRlROxhX += rM(FwCgnobGoNgycyqau);else if " ascii
    $s18 = "function QbiMGyQkPoTDWEq(zOPCQjWndlsMFuLq,IOQRuINVepVb){return zOPCQjWndlsMFuLq.indexOf(IOQRuINVepVb);}" fullword ascii
    $s19 = "function rM(MTVazklDANzsO){return String.fromCharCode(MTVazklDANzsO);}" fullword ascii
    $s20 = "function TTsKJVqjt(wEXbPazpFMXkp) {var OfrqNhZZPekKSur = clWPhWnbavj.join(OepfSGrLMdBEOOtE[6]);var FwCgnobGoNgycyqau, YYglJpHhYH" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}