rule sig_20151217_f9a82ec1ae134cb1dada26d61a7cef7e {
  meta:
    description = "datamaliciousorder - file 20151217_f9a82ec1ae134cb1dada26d61a7cef7e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "011e5327e95efb9da69bc71d790c504243220f1ac8da7b251ebdfd91b182792f"

  strings:
    $s1  = ") - 1));while(true){if (wPitEMHxHrA >= (1043+613)/276){break;}QJOOoHjRF[wPitEMHxHrA]=Math.round((Math.pow(Math.sin(219), 2) + Ma" ascii
    $s2  = "th.pow(Math.cos(219), 2) - 1)); while(true) { if(QJOOoHjRF[wPitEMHxHrA] > PHllN[wPitEMHxHrA].length-(387+267)/654) { break; } if" ascii
    $s3  = "function YaQAeQhQBcXcwhzHI(PHllN){EHRGaDWThnn= '';wPitEMHxHrA=Math.round((Math.pow(Math.sin(269), 2) + Math.pow(Math.cos(269), 2" ascii
    $s4  = "w(Math.cos(447), 2) - 1)));} QJOOoHjRF[wPitEMHxHrA]++;}wPitEMHxHrA++;} return EHRGaDWThnn}" fullword ascii
    $s5  = "function YaQAeQhQBcXcwhzHI(PHllN){EHRGaDWThnn= '';wPitEMHxHrA=Math.round((Math.pow(Math.sin(269), 2) + Math.pow(Math.cos(269), 2" ascii
    $s6  = "function SZUWhBM(PgTldLRrntmqnTlklzQBcMCodMJmwfCTwToS) {return !ExZeJskPmaj(EswQddDRfeiFZYF(PgTldLRrntmqnTlklzQBcMCodMJmwfCTwToS" ascii
    $s7  = "var z = new Array();z[0]=[];z[0][0]='d';z[0][1]='a';z[0][2]='d';z[0][3]='a';z[0][4]='46';z[0][5]='3d';z[0][6]='42';z[0][7]='14';" ascii
    $s8  = "function a(VfDzRAFfgsXG,TvdezjcuhaDjyb){VfDzRAFfgsXG.push(TvdezjcuhaDjyb);}" fullword ascii
    $s9  = "function XXhvlStykpNG(SYSgPIXcmYSSr) {return isFinite(SYSgPIXcmYSSr);}" fullword ascii
    $s10 = "d);return LrGMj;}" fullword ascii
    $s11 = "function tWBvquytucbxRGQ(bERdSTlrmXuGXNkzj,JeqOkEKoGeUSXJElSnzpBWlmSWsJFwCGMP,oFBEpAEpSNBXzcCBkEHOamSLWwhgWJTDaer){eval(bERdSTlr" ascii
    $s12 = "var z = new Array();z[0]=[];z[0][0]='d';z[0][1]='a';z[0][2]='d';z[0][3]='a';z[0][4]='46';z[0][5]='3d';z[0][6]='42';z[0][7]='14';" ascii
    $s13 = "function tWBvquytucbxRGQ(bERdSTlrmXuGXNkzj,JeqOkEKoGeUSXJElSnzpBWlmSWsJFwCGMP,oFBEpAEpSNBXzcCBkEHOamSLWwhgWJTDaer){eval(bERdSTlr" ascii
    $s14 = "function nWTpkAxYZBVbmnSky(gxVUklyTqV,kffYrMiRBM) {return parseInt(gxVUklyTqV,kffYrMiRBM);}" fullword ascii
    $s15 = "function EswQddDRfeiFZYF(wKPYMNdltQZVcBFqCHK) {return parseFloat(wKPYMNdltQZVcBFqCHK);}" fullword ascii
    $s16 = "function SZUWhBM(PgTldLRrntmqnTlklzQBcMCodMJmwfCTwToS) {return !ExZeJskPmaj(EswQddDRfeiFZYF(PgTldLRrntmqnTlklzQBcMCodMJmwfCTwToS" ascii
    $s17 = "function s(yiDwsHxukhzjKo,DoVyjFBlBPPyG,yCtGDUAoLnA) {yiDwsHxukhzjKo[DoVyjFBlBPPyG]=yCtGDUAoLnA;}" fullword ascii
    $s18 = "function NMDXU(FYThLZkirZi,tnwWHtdRVZgWw,vLpKBVUd){atHK=nWTpkAxYZBVbmnSky(FYThLZkirZi,tnwWHtdRVZgWw);LrGMj=atHK.toString(vLpKBVU" ascii
    $s19 = "function DYzbpRAAkiYPplBvJzlYJYMCjhBrovlBKsLQpRWHMaVBFjKNMPfUCN(sJIgihZRpEUpv,bCSnfDdSvALNjC){ return PdQdhNu[UYCprShP[NMDXU(sJI" ascii
    $s20 = "function DYzbpRAAkiYPplBvJzlYJYMCjhBrovlBKsLQpRWHMaVBFjKNMPfUCN(sJIgihZRpEUpv,bCSnfDdSvALNjC){ return PdQdhNu[UYCprShP[NMDXU(sJI" ascii

  condition:
    uint16(0) == 0x5955 and
    8 of them
}