rule sig_20151217_ebc1d6e6a35f5031e1ac516b9099faa0 {
  meta:
    description = "datamaliciousorder - file 20151217_ebc1d6e6a35f5031e1ac516b9099faa0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa8bc2b937b6da0c83992c9b9eee9ba02a3f4573c6352c54f2e199a8a8d66ea3"

  strings:
    $s1  = "function zOAwnGZkdccrfDlFm(HaLWX){TPwtwAvargZ= '';IMqLestcrLF=Math.round((Math.pow(Math.sin(868), 2) + Math.pow(Math.cos(868), 2" ascii
    $s2  = "ow(Math.cos(920), 2) - 1)));} zjEsDAGJq[IMqLestcrLF]++;}IMqLestcrLF++;} return TPwtwAvargZ}" fullword ascii
    $s3  = "th.pow(Math.cos(294), 2) - 1)); while(true) { if(zjEsDAGJq[IMqLestcrLF] > HaLWX[IMqLestcrLF].length-(-38+142)/104) { break; } if" ascii
    $s4  = ") - 1));while(true){if (IMqLestcrLF >= (4287+693)/830){break;}zjEsDAGJq[IMqLestcrLF]=Math.round((Math.pow(Math.sin(294), 2) + Ma" ascii
    $s5  = "function zOAwnGZkdccrfDlFm(HaLWX){TPwtwAvargZ= '';IMqLestcrLF=Math.round((Math.pow(Math.sin(868), 2) + Math.pow(Math.cos(868), 2" ascii
    $s6  = "function PjQqRgt(bteJkUYzmEXklkbcuwloFXnlZaWOnNCTVwrc) {return !odkrIvyPVNa(emLfYllzKSghJrw(bteJkUYzmEXklkbcuwloFXnlZaWOnNCTVwrc" ascii
    $s7  = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s8  = "function MXcmLzrOKPNlyAM(octyiKOasgHFOQdoC,OgsPKkgPrGJjTPzNWTkRhiWDTzQDqztJRr,sdCJtQBsZQGAFmQshqNCkJfIsMZNZvAGRxP){eval(octyiKOa" ascii
    $s9  = "function emLfYllzKSghJrw(HiaAkHCFUkVZZHgaqFE) {return parseFloat(HiaAkHCFUkVZZHgaqFE);}" fullword ascii
    $s10 = "l);return ksItG;}" fullword ascii
    $s11 = "function H(nlGKTLJWqCLn,wCknzDTsvUkJmR){nlGKTLJWqCLn.push(wCknzDTsvUkJmR);}" fullword ascii
    $s12 = "function WPdBc(vnoygLXMXIX,fDaftTRSHaSWT,CgQvAYol){FQnn=gPuSiJcqSqAVjLszs(vnoygLXMXIX,fDaftTRSHaSWT);ksItG=FQnn.toString(CgQvAYo" ascii
    $s13 = "function WPdBc(vnoygLXMXIX,fDaftTRSHaSWT,CgQvAYol){FQnn=gPuSiJcqSqAVjLszs(vnoygLXMXIX,fDaftTRSHaSWT);ksItG=FQnn.toString(CgQvAYo" ascii
    $s14 = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s15 = "function TnYUPZDHmjFB(tGDqvkYyfpvZb) {return isFinite(tGDqvkYyfpvZb);}" fullword ascii
    $s16 = "function gPuSiJcqSqAVjLszs(zKhsDHFPGA,IdNXxZIqFy) {return parseInt(zKhsDHFPGA,IdNXxZIqFy);}" fullword ascii
    $s17 = "function D(eAxEhhrgCqTyFB,ymfyGQBgHHyKU,PDxccsueFNe) {eAxEhhrgCqTyFB[ymfyGQBgHHyKU]=PDxccsueFNe;}" fullword ascii
    $s18 = "function MXcmLzrOKPNlyAM(octyiKOasgHFOQdoC,OgsPKkgPrGJjTPzNWTkRhiWDTzQDqztJRr,sdCJtQBsZQGAFmQshqNCkJfIsMZNZvAGRxP){eval(octyiKOa" ascii
    $s19 = "function PjQqRgt(bteJkUYzmEXklkbcuwloFXnlZaWOnNCTVwrc) {return !odkrIvyPVNa(emLfYllzKSghJrw(bteJkUYzmEXklkbcuwloFXnlZaWOnNCTVwrc" ascii
    $s20 = ",'*','V','_','t','K','r','W','N','0','U','K','h','X','g','Y','d','/','i','A','?','F','>','(','Z','[','H','^','g','K','v',String." ascii

  condition:
    uint16(0) == 0x486f and
    8 of them
}