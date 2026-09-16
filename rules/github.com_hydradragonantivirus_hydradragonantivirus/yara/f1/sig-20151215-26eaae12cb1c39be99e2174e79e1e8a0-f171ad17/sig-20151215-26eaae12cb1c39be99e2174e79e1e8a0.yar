rule sig_20151215_26eaae12cb1c39be99e2174e79e1e8a0 {
  meta:
    description = "datamaliciousorder - file 20151215_26eaae12cb1c39be99e2174e79e1e8a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbaa70c64d5468b44b4d6e7e9dd5598686e212af772275b4f534c9036bd684c0"

  strings:
    $s1  = "Math.pow(Math.cos(738), 2) - 1)); while(true) { if(PdBsAxhDR[yzGPsjdrbqJ] > wCYGe[yzGPsjdrbqJ].length-(256+720)/976) { break; } " ascii
    $s2  = "function kNlBIQwDLrGIDUUro(wCYGe){XUQiHtXcRqy= N[1760];for(yzGPsjdrbqJ=Math.round((Math.pow(Math.sin(948), 2) + Math.pow(Math.co" ascii
    $s3  = "h.pow(Math.cos(510), 2) - 1)));} PdBsAxhDR[yzGPsjdrbqJ]++;}} return XUQiHtXcRqy}" fullword ascii
    $s4  = "function kNlBIQwDLrGIDUUro(wCYGe){XUQiHtXcRqy= N[1760];for(yzGPsjdrbqJ=Math.round((Math.pow(Math.sin(948), 2) + Math.pow(Math.co" ascii
    $s5  = "QGak)) {return (String.fromCharCode(FFGSwfWicdkSQGak) + String.fromCharCode((22237+863)/275));}}" fullword ascii
    $s6  = "function K(KlxBassRTfli,FQSboHhJCVppGi){KlxBassRTfli.push(FQSboHhJCVppGi);}function h8(FFGSwfWicdkSQGak){if(RbYgBWU(FFGSwfWicdkS" ascii
    $s7  = "function RbYgBWU(BPsjkaatGmtFlvneEYPlyQriGqmtLVJrYMGi) {return !isNaN(parseFloat(BPsjkaatGmtFlvneEYPlyQriGqmtLVJrYMGi)) && isFin" ascii
    $s8  = "function RbYgBWU(BPsjkaatGmtFlvneEYPlyQriGqmtLVJrYMGi) {return !isNaN(parseFloat(BPsjkaatGmtFlvneEYPlyQriGqmtLVJrYMGi)) && isFin" ascii
    $s9  = "function ftTyR(dmKzJMrSuIY,JUAvQtHNQAKVx,ietGsHHT){RJKO=parseInt(dmKzJMrSuIY,JUAvQtHNQAKVx);CtfxX=RJKO.toString(ietGsHHT);return" ascii
    $s10 = "function IHXdlkmjWNRPngl(mUKibZLNqMBvdeJOn){eval(mUKibZLNqMBvdeJOn)}" fullword ascii
    $s11 = "var N=new Array();" fullword ascii
    $s12 = "function RqEQvTQrQArXGPFLnQOZrqhhimZVsAsyVJUCCmSrywfxDGWkplDCHD(wtZSBwQatfFuV,aJJqymFglrzRRv){ return UzCDGXB[SrhCVHFk[ftTyR(wtZ" ascii
    $s13 = "function ebJhyMioewK(qyQlDuCc,ROjLUm){return qyQlDuCc.split(ROjLUm)}" fullword ascii
    $s14 = "function ftTyR(dmKzJMrSuIY,JUAvQtHNQAKVx,ietGsHHT){RJKO=parseInt(dmKzJMrSuIY,JUAvQtHNQAKVx);CtfxX=RJKO.toString(ietGsHHT);return" ascii
    $s15 = " CtfxX;}function IHXdlkmjWNRPngl(mUKibZLNqMBvdeJOn,maLtrWgGtTqapQRugQqljFHiNIMguIxFLF,AsEaWnHXrOmyOgZbQiBHrgzFBFykiaqjcOQ){eval(" ascii
    $s16 = "function RqEQvTQrQArXGPFLnQOZrqhhimZVsAsyVJUCCmSrywfxDGWkplDCHD(wtZSBwQatfFuV,aJJqymFglrzRRv){ return UzCDGXB[SrhCVHFk[ftTyR(wtZ" ascii
    $s17 = "function K(KlxBassRTfli,FQSboHhJCVppGi){KlxBassRTfli.push(FQSboHhJCVppGi);}function h8(FFGSwfWicdkSQGak){if(RbYgBWU(FFGSwfWicdkS" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}