rule sig_20151216_180756300abeb54bfdc502835e7abedb {
  meta:
    description = "datamaliciousorder - file 20151216_180756300abeb54bfdc502835e7abedb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f92fb52bc5acba9c9b908574d397771b989e6ccfb9a3d09d29c9d76b747f95ef"

  strings:
    $s1  = "(Math.cos(147), 2) - 1)));} TjeCwiceE[uQfugzeOBLI]++;}uQfugzeOBLI++;} return BeCYavLIIGi}" fullword ascii
    $s2  = "function qEkLrNkGipweSeUyq(plqOb){BeCYavLIIGi= '';uQfugzeOBLI=Math.round((Math.pow(Math.sin(980), 2) + Math.pow(Math.cos(980), 2" ascii
    $s3  = "h.pow(Math.cos(697), 2) - 1)); while(true) { if(TjeCwiceE[uQfugzeOBLI] > plqOb[uQfugzeOBLI].length-(450+275)/725) { break; } if " ascii
    $s4  = ") - 1));while(true){if (uQfugzeOBLI >= (695+469)/194){break;}TjeCwiceE[uQfugzeOBLI]=Math.round((Math.pow(Math.sin(697), 2) + Mat" ascii
    $s5  = "function qEkLrNkGipweSeUyq(plqOb){BeCYavLIIGi= '';uQfugzeOBLI=Math.round((Math.pow(Math.sin(980), 2) + Math.pow(Math.cos(980), 2" ascii
    $s6  = "function lYutntLyNCoTwpU(OGskrSaZwTdAexzBH,inNptwTZrGbWJUHRkREtzmpKhbwSYbFqGf,mMLzmmWSpiAbJIzvFpXQwdbKxCsfalkUOkC){eval(OGskrSaZ" ascii
    $s7  = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s8  = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s9  = "function u(HAgUZfQrOFkc,MvvfxKXzRYxaJb){HAgUZfQrOFkc.push(MvvfxKXzRYxaJb);}" fullword ascii
    $s10 = "function L(MjfAeSJvyVlhUR,nBrvEYlQFdCeD,ePqjbnvqJwo) {MjfAeSJvyVlhUR[nBrvEYlQFdCeD]=ePqjbnvqJwo;}" fullword ascii
    $s11 = "function mcsfC(fCIaLqSRfJN,TzKXeVnRoRrJP,KbVGdXEQ){NBsP=SpaRYKSodhzxTpbAa(fCIaLqSRfJN,TzKXeVnRoRrJP);tJrby=NBsP.toString(KbVGdXE" ascii
    $s12 = "Q);return tJrby;}" fullword ascii
    $s13 = "function robFEJJdFufY(RBTOVOKoZSLSf) {return isFinite(RBTOVOKoZSLSf);}" fullword ascii
    $s14 = "function JgmHexFoFUomIqM(BpHTbZjStQlBoSXNRla) {return parseFloat(BpHTbZjStQlBoSXNRla);}" fullword ascii
    $s15 = "function INUJDCJBSTDeFOyDmmRQGFgkJKTETsGjwBjuqCgIJxZVLEylUzIJsz(ggCvXwKLmFqOp,IZZKjRaXYPAwVC){ return gzhYiKb[QyvoHEuW[mcsfC(ggC" ascii
    $s16 = "function mcsfC(fCIaLqSRfJN,TzKXeVnRoRrJP,KbVGdXEQ){NBsP=SpaRYKSodhzxTpbAa(fCIaLqSRfJN,TzKXeVnRoRrJP);tJrby=NBsP.toString(KbVGdXE" ascii
    $s17 = "function INUJDCJBSTDeFOyDmmRQGFgkJKTETsGjwBjuqCgIJxZVLEylUzIJsz(ggCvXwKLmFqOp,IZZKjRaXYPAwVC){ return gzhYiKb[QyvoHEuW[mcsfC(ggC" ascii
    $s18 = "function SpaRYKSodhzxTpbAa(yfjpgPpbiP,woKocDbVKd) {return parseInt(yfjpgPpbiP,woKocDbVKd);}" fullword ascii
    $s19 = "function lYutntLyNCoTwpU(OGskrSaZwTdAexzBH,inNptwTZrGbWJUHRkREtzmpKhbwSYbFqGf,mMLzmmWSpiAbJIzvFpXQwdbKxCsfalkUOkC){eval(OGskrSaZ" ascii
    $s20 = "function sBEowHH(sUeLiePxjgIrHUtYMYRWEbYSqAbJrHBcDHLR) {return !cARDTsEyJoP(JgmHexFoFUomIqM(sUeLiePxjgIrHUtYMYRWEbYSqAbJrHBcDHLR" ascii

  condition:
    uint16(0) == 0x7951 and
    8 of them
}