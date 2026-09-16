rule sig_20151216_c0cd6636b2fce5f380748cec125e8a14 {
  meta:
    description = "datamaliciousorder - file 20151216_c0cd6636b2fce5f380748cec125e8a14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12b1448356cbaa2dc7b243c171fc5f9591ac4554d1269dd3ddf545bc02346545"

  strings:
    $s1  = ".pow(Math.cos(135), 2) - 1)); while(true) { if(FPDQgmEOg[YbMrErDjcrL] > UpCDr[YbMrErDjcrL].length-(-701+750)/49) { break; } if (" ascii
    $s2  = "function CnTtYxCBEssRNkRrl(UpCDr){hNPKLXOBvWL= '';YbMrErDjcrL=Math.round((Math.pow(Math.sin(53), 2) + Math.pow(Math.cos(53), 2) " ascii
    $s3  = "(Math.cos(540), 2) - 1)));} FPDQgmEOg[YbMrErDjcrL]++;}YbMrErDjcrL++;} return hNPKLXOBvWL}" fullword ascii
    $s4  = "function hRJEq(TPQFElZRxIl,zazpDGdgEhAHv,VvPMYtHR){cwjq=ySkNGeTqaOZZRfSUD(TPQFElZRxIl,zazpDGdgEhAHv);ZFsDz=cwjq.toString(VvPMYtH" ascii
    $s5  = "function hRJEq(TPQFElZRxIl,zazpDGdgEhAHv,VvPMYtHR){cwjq=ySkNGeTqaOZZRfSUD(TPQFElZRxIl,zazpDGdgEhAHv);ZFsDz=cwjq.toString(VvPMYtH" ascii
    $s6  = "function ySkNGeTqaOZZRfSUD(sLnaTVOWVb,pAPqajhYbK) {return parseInt(sLnaTVOWVb,pAPqajhYbK);}" fullword ascii
    $s7  = "function uoJmGTC(rsHuBoaVZMGQGeUsBiGroLUXyYyVAsnuujms) {return !VPqmOCFmxMS(KxKRXCQiVbjyrRb(rsHuBoaVZMGQGeUsBiGroLUXyYyVAsnuujms" ascii
    $s8  = "function CnTtYxCBEssRNkRrl(UpCDr){hNPKLXOBvWL= '';YbMrErDjcrL=Math.round((Math.pow(Math.sin(53), 2) + Math.pow(Math.cos(53), 2) " ascii
    $s9  = "- 1));while(true){if (YbMrErDjcrL >= (1138+296)/239){break;}FPDQgmEOg[YbMrErDjcrL]=Math.round((Math.pow(Math.sin(135), 2) + Math" ascii
    $s10 = "var N = new Array();N[0]=[];N[0][0]='d';N[0][1]='a';N[0][2]='d';N[0][3]='a';N[0][4]='46';N[0][5]='3d';N[0][6]='42';N[0][7]='14';" ascii
    $s11 = ",'h','e','V','f','#','W','j','1','7','z','-','X','n','u','-','7','$','Y','R','0','$','[','=','Z','[','2','y','z','-','7',String." ascii
    $s12 = "function KxKRXCQiVbjyrRb(RsvUrrYwGXhmSaXQDpQ) {return parseFloat(RsvUrrYwGXhmSaXQDpQ);}" fullword ascii
    $s13 = "function uoJmGTC(rsHuBoaVZMGQGeUsBiGroLUXyYyVAsnuujms) {return !VPqmOCFmxMS(KxKRXCQiVbjyrRb(rsHuBoaVZMGQGeUsBiGroLUXyYyVAsnuujms" ascii
    $s14 = "function ViEqhtsqMzSJ(NUimPmrZHbmYM) {return isFinite(NUimPmrZHbmYM);}" fullword ascii
    $s15 = "R);return ZFsDz;}" fullword ascii
    $s16 = "function VPqmOCFmxMS(JIQcNmeiUlCFKg) {return isNaN(JIQcNmeiUlCFKg);}" fullword ascii
    $s17 = "function dEJtGhvhtFzQcxN(tdXPAoBPhGBOrylLb,HQeDyiPGpZCQPMamjoBaXrEUhBokdTDtYk,EkUMmzAAsHcpBUcwPHzYNKDqkVYWJAXCIwJ){eval(tdXPAoBP" ascii
    $s18 = "function Z(CbPRGauwquMC,ItFUAZEHwfCDJJ){CbPRGauwquMC.push(ItFUAZEHwfCDJJ);}" fullword ascii
    $s19 = "var N = new Array();N[0]=[];N[0][0]='d';N[0][1]='a';N[0][2]='d';N[0][3]='a';N[0][4]='46';N[0][5]='3d';N[0][6]='42';N[0][7]='14';" ascii
    $s20 = "function dEJtGhvhtFzQcxN(tdXPAoBPhGBOrylLb,HQeDyiPGpZCQPMamjoBaXrEUhBokdTDtYk,EkUMmzAAsHcpBUcwPHzYNKDqkVYWJAXCIwJ){eval(tdXPAoBP" ascii

  condition:
    uint16(0) == 0x7768 and
    8 of them
}