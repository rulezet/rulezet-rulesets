rule sig_20151216_0758a093fb879b495148828f5302e03d {
  meta:
    description = "datamaliciousorder - file 20151216_0758a093fb879b495148828f5302e03d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92cf698dd086b2276dc8a48f7509415403c464330b339130e48571fb897447c5"

  strings:
    $s1  = "h.pow(Math.cos(957), 2) - 1)); while(true) { if(iMNxdxZxH[NjmZbQdqmOV] > cEHXw[NjmZbQdqmOV].length-(-507+803)/296) { break; } if" ascii
    $s2  = ") - 1));while(true){if (NjmZbQdqmOV >= (710+340)/175){break;}iMNxdxZxH[NjmZbQdqmOV]=Math.round((Math.pow(Math.sin(957), 2) + Mat" ascii
    $s3  = "pow(Math.cos(301), 2) - 1)));} iMNxdxZxH[NjmZbQdqmOV]++;}NjmZbQdqmOV++;} return YHHphfpbraD}" fullword ascii
    $s4  = "function iHyPReXcXjmvrfgmN(cEHXw){YHHphfpbraD= '';NjmZbQdqmOV=Math.round((Math.pow(Math.sin(422), 2) + Math.pow(Math.cos(422), 2" ascii
    $s5  = "function iHyPReXcXjmvrfgmN(cEHXw){YHHphfpbraD= '';NjmZbQdqmOV=Math.round((Math.pow(Math.sin(422), 2) + Math.pow(Math.cos(422), 2" ascii
    $s6  = "function QPrcFOW(otsXQCYYZvKEVmwOJXRFsqLYUpRiWFmpREqK) {return !qCXCdtEQfcH(GIjsabhsJhQGkCJ(otsXQCYYZvKEVmwOJXRFsqLYUpRiWFmpREqK" ascii
    $s7  = "LnpDuoXICAdyZnPyIoohKCSnnpexNPVTvCC([cEHXw[NjmZbQdqmOV][iMNxdxZxH[NjmZbQdqmOV]]], Math.round((Math.pow(Math.sin(301), 2) + Math." ascii
    $s8  = "var P = new Array();P[0]=[];P[0][0]='d';P[0][1]='a';P[0][2]='d';P[0][3]='a';P[0][4]='46';P[0][5]='3d';P[0][6]='42';P[0][7]='14';" ascii
    $s9  = "function gNPnOEgjttEe(SBhqaOHwHEgNJ) {return isFinite(SBhqaOHwHEgNJ);}" fullword ascii
    $s10 = "function C(twSRBleLOnAJ,BjUTDMRQaRAzqw){twSRBleLOnAJ.push(BjUTDMRQaRAzqw);}" fullword ascii
    $s11 = "function BYksYteJwLUchcv(qjAGYobDKTfWOJofp,dbxUDjNmZRvJPJiXGHrHJvWtxCBpZrirvI,VeVyMJAiVCOQulVpXxIVOiFrWXgmqrVjAiI){eval(qjAGYobD" ascii
    $s12 = "function BYksYteJwLUchcv(qjAGYobDKTfWOJofp,dbxUDjNmZRvJPJiXGHrHJvWtxCBpZrirvI,VeVyMJAiVCOQulVpXxIVOiFrWXgmqrVjAiI){eval(qjAGYobD" ascii
    $s13 = "function qCXCdtEQfcH(pynMFTBluXWJBp) {return isNaN(pynMFTBluXWJBp);}" fullword ascii
    $s14 = "function wotfeXPEpdevlqcYC(AgDufmFEnj,AanJZrOjBm) {return parseInt(AgDufmFEnj,AanJZrOjBm);}" fullword ascii
    $s15 = "var P = new Array();P[0]=[];P[0][0]='d';P[0][1]='a';P[0][2]='d';P[0][3]='a';P[0][4]='46';P[0][5]='3d';P[0][6]='42';P[0][7]='14';" ascii
    $s16 = "m);return yQxGO;}" fullword ascii
    $s17 = "function GIjsabhsJhQGkCJ(zDnhRbBeZmYvAMMfHdB) {return parseFloat(zDnhRbBeZmYvAMMfHdB);}" fullword ascii
    $s18 = "function QPrcFOW(otsXQCYYZvKEVmwOJXRFsqLYUpRiWFmpREqK) {return !qCXCdtEQfcH(GIjsabhsJhQGkCJ(otsXQCYYZvKEVmwOJXRFsqLYUpRiWFmpREqK" ascii
    $s19 = "function h(ENxtqnGMJjJzky,DLRcxQraHwihx,CemMazfiJiW) {ENxtqnGMJjJzky[DLRcxQraHwihx]=CemMazfiJiW;}" fullword ascii
    $s20 = "function XmsKfSNZsHOgPDQmpunLnpDuoXICAdyZnPyIoohKCSnnpexNPVTvCC(SzVIiVpXnjchV,GfLYiINzDmIegS){ return tXYhsVR[qDnNdfnN[VOBCa(SzV" ascii

  condition:
    uint16(0) == 0x4471 and
    8 of them
}