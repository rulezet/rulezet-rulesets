rule sig_20151216_c4139e2b4e74636fabda9a7356d7be1a {
  meta:
    description = "datamaliciousorder - file 20151216_c4139e2b4e74636fabda9a7356d7be1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "880cd6dc7710b4eb16d673b47ec1a7c74dd0873dd7f6b82808b67014002be6a2"

  strings:
    $s1  = "Math.cos(26), 2) - 1)));} mIeFHwtSh[gbjemzcKgVi]++;}gbjemzcKgVi++;} return xKMSGWLdfYw}" fullword ascii
    $s2  = "th.pow(Math.cos(544), 2) - 1)); while(true) { if(mIeFHwtSh[gbjemzcKgVi] > BRzOi[gbjemzcKgVi].length-(136+622)/758) { break; } if" ascii
    $s3  = ") - 1));while(true){if (gbjemzcKgVi >= (1495+587)/347){break;}mIeFHwtSh[gbjemzcKgVi]=Math.round((Math.pow(Math.sin(544), 2) + Ma" ascii
    $s4  = "function QwXEHNxziyJMLDNuP(BRzOi){xKMSGWLdfYw= '';gbjemzcKgVi=Math.round((Math.pow(Math.sin(617), 2) + Math.pow(Math.cos(617), 2" ascii
    $s5  = "function QwXEHNxziyJMLDNuP(BRzOi){xKMSGWLdfYw= '';gbjemzcKgVi=Math.round((Math.pow(Math.sin(617), 2) + Math.pow(Math.cos(617), 2" ascii
    $s6  = "function qFZEXaf(FAgEhutNwnEyTQEGAPgdJmMQwioNBldhMfxT) {return !vShxkXTRoiN(PKYbBNSiUDMwMdk(FAgEhutNwnEyTQEGAPgdJmMQwioNBldhMfxT" ascii
    $s7  = "function H(sawNEJqJeLapvD,kodkUahVDWijV,ZPwUBaXsEmc) {sawNEJqJeLapvD[kodkUahVDWijV]=ZPwUBaXsEmc;}" fullword ascii
    $s8  = "function UvMdjigWTujxzhKGGZTWhedXFCQMVyVRJqYcGYizhSCOIfyuQeXTOO(DvceHnWBCMktX,foaxOhUjhFiasb){ return eqdGDmu[mCNYbSEN[YkHiq(Dvc" ascii
    $s9  = "var Y = new Array();Y[0]=[];Y[0][0]='d';Y[0][1]='a';Y[0][2]='d';Y[0][3]='a';Y[0][4]='46';Y[0][5]='3d';Y[0][6]='42';Y[0][7]='14';" ascii
    $s10 = "function qFZEXaf(FAgEhutNwnEyTQEGAPgdJmMQwioNBldhMfxT) {return !vShxkXTRoiN(PKYbBNSiUDMwMdk(FAgEhutNwnEyTQEGAPgdJmMQwioNBldhMfxT" ascii
    $s11 = "function YkHiq(UsQTdtzQpYc,bkleKJOrtifGP,pibUjoil){pHHG=pBvqBmPKoVWKcOPWT(UsQTdtzQpYc,bkleKJOrtifGP);sPVWJ=pHHG.toString(pibUjoi" ascii
    $s12 = "function JVOWCCfhrMAUrHP(lUAMkKQCnqmqkOUyj,rNKloTNwxwlxLZjfxlYhTnEMFVxrmvziJY,nyKKLmlyHXvSwwrkDhlGOWslhbjMLXoMCej){eval(lUAMkKQC" ascii
    $s13 = "function vShxkXTRoiN(UuUCDvNAjLMwPT) {return isNaN(UuUCDvNAjLMwPT);}" fullword ascii
    $s14 = "function pBvqBmPKoVWKcOPWT(LBMKlGYgHO,fwnzPbwaHe) {return parseInt(LBMKlGYgHO,fwnzPbwaHe);}" fullword ascii
    $s15 = "function lLyexqUxrERD(ySuFHEoYpzAyL) {return isFinite(ySuFHEoYpzAyL);}" fullword ascii
    $s16 = "function YkHiq(UsQTdtzQpYc,bkleKJOrtifGP,pibUjoil){pHHG=pBvqBmPKoVWKcOPWT(UsQTdtzQpYc,bkleKJOrtifGP);sPVWJ=pHHG.toString(pibUjoi" ascii
    $s17 = "function p(hzaJnnvGYwFA,UyDAELQzwTHvWg){hzaJnnvGYwFA.push(UyDAELQzwTHvWg);}" fullword ascii
    $s18 = "l);return sPVWJ;}" fullword ascii
    $s19 = "function PKYbBNSiUDMwMdk(oAuPbTCLYeqXmdyNbDM) {return parseFloat(oAuPbTCLYeqXmdyNbDM);}" fullword ascii
    $s20 = "function UvMdjigWTujxzhKGGZTWhedXFCQMVyVRJqYcGYizhSCOIfyuQeXTOO(DvceHnWBCMktX,foaxOhUjhFiasb){ return eqdGDmu[mCNYbSEN[YkHiq(Dvc" ascii

  condition:
    uint16(0) == 0x436d and
    8 of them
}