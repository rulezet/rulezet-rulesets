rule sig_20151217_e889d44d51eb1c327109c9dd16b4b779 {
  meta:
    description = "datamaliciousorder - file 20151217_e889d44d51eb1c327109c9dd16b4b779.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7177bf173c4edc7c3c969cd44ec4439cdd2133c6eebf6eddad5a65a1fd4731e"

  strings:
    $s1  = ") - 1));while(true){if (yCfyhwlNHCQ >= (3592+974)/761){break;}hoguGxrFj[yCfyhwlNHCQ]=Math.round((Math.pow(Math.sin(906), 2) + Ma" ascii
    $s2  = "th.pow(Math.cos(906), 2) - 1)); while(true) { if(hoguGxrFj[yCfyhwlNHCQ] > pAaSf[yCfyhwlNHCQ].length-(-245+917)/672) { break; } i" ascii
    $s3  = "function GLXPjjPNFCQUetXdC(pAaSf){jcpGSTOofxi= '';yCfyhwlNHCQ=Math.round((Math.pow(Math.sin(467), 2) + Math.pow(Math.cos(467), 2" ascii
    $s4  = "pow(Math.cos(159), 2) - 1)));} hoguGxrFj[yCfyhwlNHCQ]++;}yCfyhwlNHCQ++;} return jcpGSTOofxi}" fullword ascii
    $s5  = "function GLXPjjPNFCQUetXdC(pAaSf){jcpGSTOofxi= '';yCfyhwlNHCQ=Math.round((Math.pow(Math.sin(467), 2) + Math.pow(Math.cos(467), 2" ascii
    $s6  = "zMMKejmQBrMAkNgnwpPKJTqDTasJRAUOrqi([pAaSf[yCfyhwlNHCQ][hoguGxrFj[yCfyhwlNHCQ]]], Math.round((Math.pow(Math.sin(159), 2) + Math." ascii
    $s7  = "function H(FcoMNJFzxDvvTN,lVxhlBurIlzuo,SCGmHqDrewX) {FcoMNJFzxDvvTN[lVxhlBurIlzuo]=SCGmHqDrewX;}" fullword ascii
    $s8  = "function HXogaOw(ylChndBmOuJXYQiMrYnedagHXnApefDzWClo) {return !IByVeTUBvfH(zYRbetxvnmxsaGB(ylChndBmOuJXYQiMrYnedagHXnApefDzWClo" ascii
    $s9  = "var f = new Array();f[0]=[];f[0][0]='d';f[0][1]='a';f[0][2]='d';f[0][3]='a';f[0][4]='46';f[0][5]='3d';f[0][6]='42';f[0][7]='14';" ascii
    $s10 = "function HXogaOw(ylChndBmOuJXYQiMrYnedagHXnApefDzWClo) {return !IByVeTUBvfH(zYRbetxvnmxsaGB(ylChndBmOuJXYQiMrYnedagHXnApefDzWClo" ascii
    $s11 = "function YSwlaVvuCmhQHoy(VZmwtkMaVniuOYoRg,CgiIfgjNjvDGWJRpHwpWfRFmrvpNuSrHBH,lgSDlDheaAhJNRuWgmMGguMDDeECsCtFLEz){eval(VZmwtkMa" ascii
    $s12 = "function ktBNQ(WqqSCDjuqxH,nanfJdTODhtMq,FjoyEaTI){KbSt=KcCSwxGIbdckUkoPQ(WqqSCDjuqxH,nanfJdTODhtMq);hAVTg=KbSt.toString(FjoyEaT" ascii
    $s13 = "var f = new Array();f[0]=[];f[0][0]='d';f[0][1]='a';f[0][2]='d';f[0][3]='a';f[0][4]='46';f[0][5]='3d';f[0][6]='42';f[0][7]='14';" ascii
    $s14 = "function zYRbetxvnmxsaGB(cbLxFTZtuZQonBytHyO) {return parseFloat(cbLxFTZtuZQonBytHyO);}" fullword ascii
    $s15 = "function zupkMzchtnMK(NhqLNeIfZlvuT) {return isFinite(NhqLNeIfZlvuT);}" fullword ascii
    $s16 = "function PAcryHCPWiQfIGlCcuQzMMKejmQBrMAkNgnwpPKJTqDTasJRAUOrqi(jlihmHlUipeFS,khsCzhxdPngGLL){ return WLDJmWt[WtgDwfVR[ktBNQ(jli" ascii
    $s17 = "I);return hAVTg;}" fullword ascii
    $s18 = ",'#','^','V','o','>','W',',','<','^','r','A','$','X','J','A','p','V','Y','K','Z','T','l','a','s','Q','[','2',']','/','U',String." ascii
    $s19 = "function IByVeTUBvfH(qSFVhoSIQLsNAF) {return isNaN(qSFVhoSIQLsNAF);}" fullword ascii
    $s20 = "function KcCSwxGIbdckUkoPQ(GCKXWttrab,GjdcdGkBbb) {return parseInt(GCKXWttrab,GjdcdGkBbb);}" fullword ascii

  condition:
    uint16(0) == 0x7457 and
    8 of them
}