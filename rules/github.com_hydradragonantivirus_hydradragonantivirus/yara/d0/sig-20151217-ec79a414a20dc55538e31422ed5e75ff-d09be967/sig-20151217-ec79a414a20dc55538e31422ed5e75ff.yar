rule sig_20151217_ec79a414a20dc55538e31422ed5e75ff {
  meta:
    description = "datamaliciousorder - file 20151217_ec79a414a20dc55538e31422ed5e75ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe6bf0238cf3b9125bab0c9e8d6177c2a5a2cf02dcb2b443b4074901f3919b23"

  strings:
    $s1  = ") - 1));while(true){if (HCuomXpunuk >= (2683+299)/497){break;}wvWVaYPqG[HCuomXpunuk]=Math.round((Math.pow(Math.sin(438), 2) + Ma" ascii
    $s2  = "(Math.cos(58), 2) - 1)));} wvWVaYPqG[HCuomXpunuk]++;}HCuomXpunuk++;} return ztYzghubIpI}" fullword ascii
    $s3  = "th.pow(Math.cos(438), 2) - 1)); while(true) { if(wvWVaYPqG[HCuomXpunuk] > ZvNnT[HCuomXpunuk].length-(-13+506)/493) { break; } if" ascii
    $s4  = "function AtYvqgXIYrrYgMYYs(ZvNnT){ztYzghubIpI= '';HCuomXpunuk=Math.round((Math.pow(Math.sin(801), 2) + Math.pow(Math.cos(801), 2" ascii
    $s5  = "function AtYvqgXIYrrYgMYYs(ZvNnT){ztYzghubIpI= '';HCuomXpunuk=Math.round((Math.pow(Math.sin(801), 2) + Math.pow(Math.cos(801), 2" ascii
    $s6  = "function cVNPlSV(QLRkwwgnjEjTNYehXXtLNAJXFwEUXrFmgwZc) {return !XdOjNmWTcJC(UzkWazlYKOSccVC(QLRkwwgnjEjTNYehXXtLNAJXFwEUXrFmgwZc" ascii
    $s7  = "var F = new Array();F[0]=[];F[0][0]='d';F[0][1]='a';F[0][2]='d';F[0][3]='a';F[0][4]='46';F[0][5]='3d';F[0][6]='42';F[0][7]='14';" ascii
    $s8  = "function DPmtnplXrAhIOoqPFbeTDaDZAKLVxcNihFubGRHidAzvklSDGYcLyx(BcqNhPeMxuDdu,AjYmRBjgJpvaTP){ return AVTPQtn[MLHcmEeZ[zNoEx(Bcq" ascii
    $s9  = "function DPmtnplXrAhIOoqPFbeTDaDZAKLVxcNihFubGRHidAzvklSDGYcLyx(BcqNhPeMxuDdu,AjYmRBjgJpvaTP){ return AVTPQtn[MLHcmEeZ[zNoEx(Bcq" ascii
    $s10 = "G);return rhPGc;}" fullword ascii
    $s11 = "function zNoEx(GxuPAzBKTig,yOCZjnQsALTgB,DzplqpnG){GQsx=jnbwgwxnAQWLjUgCS(GxuPAzBKTig,yOCZjnQsALTgB);rhPGc=GQsx.toString(Dzplqpn" ascii
    $s12 = "function cVNPlSV(QLRkwwgnjEjTNYehXXtLNAJXFwEUXrFmgwZc) {return !XdOjNmWTcJC(UzkWazlYKOSccVC(QLRkwwgnjEjTNYehXXtLNAJXFwEUXrFmgwZc" ascii
    $s13 = "function zNoEx(GxuPAzBKTig,yOCZjnQsALTgB,DzplqpnG){GQsx=jnbwgwxnAQWLjUgCS(GxuPAzBKTig,yOCZjnQsALTgB);rhPGc=GQsx.toString(Dzplqpn" ascii
    $s14 = "function XdOjNmWTcJC(yuJscgGgYNmLkb) {return isNaN(yuJscgGgYNmLkb);}" fullword ascii
    $s15 = "var F = new Array();F[0]=[];F[0][0]='d';F[0][1]='a';F[0][2]='d';F[0][3]='a';F[0][4]='46';F[0][5]='3d';F[0][6]='42';F[0][7]='14';" ascii
    $s16 = "function UzkWazlYKOSccVC(wFQbGuHfCgmeVchHUdn) {return parseFloat(wFQbGuHfCgmeVchHUdn);}" fullword ascii
    $s17 = "function h(saqfKHsLAQrF,mcjWqoCdzCtCCo){saqfKHsLAQrF.push(mcjWqoCdzCtCCo);}" fullword ascii
    $s18 = "function NWnzJhJcVwZNMaV(URqeZCwSHCDbtUdaf,KPzDmAZJHxybSscUokmsHoTAlGGkWeWQAV,JZhwEuoNUPqdltlKvVwMfdmYnfwsKKKZNDe){eval(URqeZCwS" ascii
    $s19 = "function jnbwgwxnAQWLjUgCS(VEZVIhlxWt,PwGxuxZLqG) {return parseInt(VEZVIhlxWt,PwGxuxZLqG);}" fullword ascii
    $s20 = "function u(fvXEmPKWdscjmJ,dQiWdqKcrvkwd,mpzOlQFqfDF) {fvXEmPKWdscjmJ[dQiWdqKcrvkwd]=mpzOlQFqfDF;}" fullword ascii

  condition:
    uint16(0) == 0x4c4d and
    8 of them
}