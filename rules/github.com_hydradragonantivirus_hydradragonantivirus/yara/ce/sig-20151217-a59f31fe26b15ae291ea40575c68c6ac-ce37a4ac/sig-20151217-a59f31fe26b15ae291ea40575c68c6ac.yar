rule sig_20151217_a59f31fe26b15ae291ea40575c68c6ac {
  meta:
    description = "datamaliciousorder - file 20151217_a59f31fe26b15ae291ea40575c68c6ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "693404522ba22b3cb8e6b2beb27634e576ef76f998ec041be1b061509d887d00"

  strings:
    $s1  = "ow(Math.cos(936), 2) - 1)));} yFuHgRKmA[DCtMSynuDCO]++;}DCtMSynuDCO++;} return DQPTKjJmgsl}" fullword ascii
    $s2  = "function xlQvyiwWvvKINEdaV(XIErM){DQPTKjJmgsl= '';DCtMSynuDCO=Math.round((Math.pow(Math.sin(238), 2) + Math.pow(Math.cos(238), 2" ascii
    $s3  = "h.pow(Math.cos(738), 2) - 1)); while(true) { if(yFuHgRKmA[DCtMSynuDCO] > XIErM[DCtMSynuDCO].length-(-521+552)/31) { break; } if " ascii
    $s4  = ") - 1));while(true){if (DCtMSynuDCO >= (319+761)/180){break;}yFuHgRKmA[DCtMSynuDCO]=Math.round((Math.pow(Math.sin(738), 2) + Mat" ascii
    $s5  = "function xlQvyiwWvvKINEdaV(XIErM){DQPTKjJmgsl= '';DCtMSynuDCO=Math.round((Math.pow(Math.sin(238), 2) + Math.pow(Math.cos(238), 2" ascii
    $s6  = "function MIywuJL(nnUuEDGemJLJVxnQExyVYsxfyYeXSjuxkCBB) {return !ZsmFxlQjiaz(XwpzwZAOuEqAMDL(nnUuEDGemJLJVxnQExyVYsxfyYeXSjuxkCBB" ascii
    $s7  = "function uJQocJvsPwHVGVT(GrCuEXlYFbexYCGEv,fKTmypJzgbclkqMUkdCupyMRHFxwmLPLyI,YWEWvWxURMEJbOGcGVnwRxwQFcZXksFBcMd){eval(GrCuEXlY" ascii
    $s8  = "function uJQocJvsPwHVGVT(GrCuEXlYFbexYCGEv,fKTmypJzgbclkqMUkdCupyMRHFxwmLPLyI,YWEWvWxURMEJbOGcGVnwRxwQFcZXksFBcMd){eval(GrCuEXlY" ascii
    $s9  = "var s = new Array();s[0]=[];s[0][0]='d';s[0][1]='a';s[0][2]='d';s[0][3]='a';s[0][4]='46';s[0][5]='3d';s[0][6]='42';s[0][7]='14';" ascii
    $s10 = "function TmTcGDOgKWUP(VQHYzgkLPtvBL) {return isFinite(VQHYzgkLPtvBL);}" fullword ascii
    $s11 = "function Y(SgxcBNFViglbMi,ypkzhhauRBKCu,BqpzhpxcNje) {SgxcBNFViglbMi[ypkzhhauRBKCu]=BqpzhpxcNje;}" fullword ascii
    $s12 = "function SwIJv(mPpynZgJfKr,zbaFIqVPxgANS,yGNULLEZ){QCzl=ojGovckeUpyIEvuqf(mPpynZgJfKr,zbaFIqVPxgANS);RjKIN=QCzl.toString(yGNULLE" ascii
    $s13 = "var s = new Array();s[0]=[];s[0][0]='d';s[0][1]='a';s[0][2]='d';s[0][3]='a';s[0][4]='46';s[0][5]='3d';s[0][6]='42';s[0][7]='14';" ascii
    $s14 = "function ZsmFxlQjiaz(dvaDMrONdZyNWc) {return isNaN(dvaDMrONdZyNWc);}" fullword ascii
    $s15 = "function XwpzwZAOuEqAMDL(VcYiSOdcwGUQSxUfjfu) {return parseFloat(VcYiSOdcwGUQSxUfjfu);}" fullword ascii
    $s16 = "function KZYwAyXCVEOXPTjZtyoHhBfIHlyoHOiWnUtWxbNnMNYhXPiKqxtHtW(JlQwxtRafPJGH,obOhbFwynpiJzo){ return AgKRtHw[GyYUEgZQ[SwIJv(JlQ" ascii
    $s17 = "function MIywuJL(nnUuEDGemJLJVxnQExyVYsxfyYeXSjuxkCBB) {return !ZsmFxlQjiaz(XwpzwZAOuEqAMDL(nnUuEDGemJLJVxnQExyVYsxfyYeXSjuxkCBB" ascii
    $s18 = "function ojGovckeUpyIEvuqf(rfiEojXkXC,HTFwAmdkbv) {return parseInt(rfiEojXkXC,HTFwAmdkbv);}" fullword ascii
    $s19 = "function KZYwAyXCVEOXPTjZtyoHhBfIHlyoHOiWnUtWxbNnMNYhXPiKqxtHtW(JlQwxtRafPJGH,obOhbFwynpiJzo){ return AgKRtHw[GyYUEgZQ[SwIJv(JlQ" ascii
    $s20 = "function v(GERAAYDRylWT,KqfuJSFnBVHgpA){GERAAYDRylWT.push(KqfuJSFnBVHgpA);}" fullword ascii

  condition:
    uint16(0) == 0x7947 and
    8 of them
}