rule sig_20151217_f9e8a9c9120d4be1d952c128dfa438ec {
  meta:
    description = "datamaliciousorder - file 20151217_f9e8a9c9120d4be1d952c128dfa438ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "265502c06e6ef47523be97ea000957e53bb33d404c105eec624e1c0a675f50f2"

  strings:
    $s1  = ") - 1));while(true){if (DYWKtsGMBeJ >= (1298+454)/292){break;}ZPuGstSMH[DYWKtsGMBeJ]=Math.round((Math.pow(Math.sin(842), 2) + Ma" ascii
    $s2  = "th.pow(Math.cos(842), 2) - 1)); while(true) { if(ZPuGstSMH[DYWKtsGMBeJ] > UjHvm[DYWKtsGMBeJ].length-(-90+929)/839) { break; } if" ascii
    $s3  = "pow(Math.cos(113), 2) - 1)));} ZPuGstSMH[DYWKtsGMBeJ]++;}DYWKtsGMBeJ++;} return grsLWSWzQfB}" fullword ascii
    $s4  = "function SZSGDsDebBTVvXoLz(UjHvm){grsLWSWzQfB= '';DYWKtsGMBeJ=Math.round((Math.pow(Math.sin(462), 2) + Math.pow(Math.cos(462), 2" ascii
    $s5  = "function SZSGDsDebBTVvXoLz(UjHvm){grsLWSWzQfB= '';DYWKtsGMBeJ=Math.round((Math.pow(Math.sin(462), 2) + Math.pow(Math.cos(462), 2" ascii
    $s6  = "BwylvwDFqSskoWYbCVNPQQvJNtJILnyIyVT([UjHvm[DYWKtsGMBeJ][ZPuGstSMH[DYWKtsGMBeJ]]], Math.round((Math.pow(Math.sin(113), 2) + Math." ascii
    $s7  = "function wSzMjKG(tUGnLAZQUkCFaKAUoFkdaWsIuzmGNwlruojQ) {return !mGWiTpzxFEW(tCMeFYBGerYBwDh(tUGnLAZQUkCFaKAUoFkdaWsIuzmGNwlruojQ" ascii
    $s8  = "var G = new Array();G[0]=[];G[0][0]='d';G[0][1]='a';G[0][2]='d';G[0][3]='a';G[0][4]='46';G[0][5]='3d';G[0][6]='42';G[0][7]='14';" ascii
    $s9  = "function mGWiTpzxFEW(qdglzHPsYhykOx) {return isNaN(qdglzHPsYhykOx);}" fullword ascii
    $s10 = "function JECoenVRbjTngurLFlQBwylvwDFqSskoWYbCVNPQQvJNtJILnyIyVT(qxQJrDkjyymwp,dLBfjPCZxaZIlH){ return rwTidZW[WBaVLIik[KyFbm(qxQ" ascii
    $s11 = "function tCMeFYBGerYBwDh(NrQuNwOygpxttOwRGlp) {return parseFloat(NrQuNwOygpxttOwRGlp);}" fullword ascii
    $s12 = "function JECoenVRbjTngurLFlQBwylvwDFqSskoWYbCVNPQQvJNtJILnyIyVT(qxQJrDkjyymwp,dLBfjPCZxaZIlH){ return rwTidZW[WBaVLIik[KyFbm(qxQ" ascii
    $s13 = ",'H','X','V','w','W','L',')','&','X','b','S','X','m',' ','1','U',']','Y','y','2','z','[','Z','Q','T','M','M','[','D','k',String." ascii
    $s14 = "function ibaCEsJBWMAyroOrP(vAlxrbMXan,yHwcsufzGD) {return parseInt(vAlxrbMXan,yHwcsufzGD);}" fullword ascii
    $s15 = "C);return lRMEB;}" fullword ascii
    $s16 = "function wSzMjKG(tUGnLAZQUkCFaKAUoFkdaWsIuzmGNwlruojQ) {return !mGWiTpzxFEW(tCMeFYBGerYBwDh(tUGnLAZQUkCFaKAUoFkdaWsIuzmGNwlruojQ" ascii
    $s17 = "function oibtIcUEfRAnHEZ(gnCtHaUdvwoBFeDWl,GkWNIVYuAatcNblWBcHGoyxVOGKBSxzGsK,cpJNMnCUMhiZStuaBacUtZUKAPfjSMYvXqW){eval(gnCtHaUd" ascii
    $s18 = "function ZywMsrRoUUiB(wjQFWpVHqfoiT) {return isFinite(wjQFWpVHqfoiT);}" fullword ascii
    $s19 = "function KyFbm(AxUQADvNRQa,wOauZotaPvWrT,tPpWOQiC){jyGk=ibaCEsJBWMAyroOrP(AxUQADvNRQa,wOauZotaPvWrT);lRMEB=jyGk.toString(tPpWOQi" ascii
    $s20 = "var G = new Array();G[0]=[];G[0][0]='d';G[0][1]='a';G[0][2]='d';G[0][3]='a';G[0][4]='46';G[0][5]='3d';G[0][6]='42';G[0][7]='14';" ascii

  condition:
    uint16(0) == 0x4257 and
    8 of them
}