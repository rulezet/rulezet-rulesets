rule sig_20151217_339e1a25aa568a3531a1b2b2eb2ae43b {
  meta:
    description = "datamaliciousorder - file 20151217_339e1a25aa568a3531a1b2b2eb2ae43b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f87b2e3489a2692ac54c2ee82b7df4f40db3424829522d38f5fa97c109a68ebe"

  strings:
    $s1  = ") - 1));while(true){if (vFBESOdhTbK >= (5010+600)/935){break;}lLJtufsnv[vFBESOdhTbK]=Math.round((Math.pow(Math.sin(142), 2) + Ma" ascii
    $s2  = "function dsItTMKxXDNiZoCxO(QftTD){tEEzXHPbvHQ= '';vFBESOdhTbK=Math.round((Math.pow(Math.sin(623), 2) + Math.pow(Math.cos(623), 2" ascii
    $s3  = "th.pow(Math.cos(142), 2) - 1)); while(true) { if(lLJtufsnv[vFBESOdhTbK] > QftTD[vFBESOdhTbK].length-(-264+269)/5) { break; } if " ascii
    $s4  = "(Math.cos(335), 2) - 1)));} lLJtufsnv[vFBESOdhTbK]++;}vFBESOdhTbK++;} return tEEzXHPbvHQ}" fullword ascii
    $s5  = "function dsItTMKxXDNiZoCxO(QftTD){tEEzXHPbvHQ= '';vFBESOdhTbK=Math.round((Math.pow(Math.sin(623), 2) + Math.pow(Math.cos(623), 2" ascii
    $s6  = "function HGIbdvo(fAXiYzFLjwDyJmhAAwYrQVYQnytbAeOgEFtF) {return !QXXALTrnhWz(aZtzxPnNwYEoSCF(fAXiYzFLjwDyJmhAAwYrQVYQnytbAeOgEFtF" ascii
    $s7  = "var o = new Array();o[0]=[];o[0][0]='d';o[0][1]='a';o[0][2]='d';o[0][3]='a';o[0][4]='46';o[0][5]='3d';o[0][6]='42';o[0][7]='14';" ascii
    $s8  = "function dvOGvFQaHsOYqSZ(spDgbCqbXUXkrpemw,EPBSMkwHnKYMoKoVNuUHlgrTxZNjGsFPbO,xVNUbqjSAeWaoOFdsMUKORWyScWqaGFMVns){eval(spDgbCqb" ascii
    $s9  = "function QzjDTSgfthQNbGQuE(TOSkdtSwPh,OSaEkxOMqu) {return parseInt(TOSkdtSwPh,OSaEkxOMqu);}" fullword ascii
    $s10 = "function rCqFKPHxwfMx(OINdwQnWQPFdz) {return isFinite(OINdwQnWQPFdz);}" fullword ascii
    $s11 = "O);return MZUnX;}" fullword ascii
    $s12 = "function nNjcrfuxkOGXyVoRcYvFpQuQtBaOSdPOJPmVkVCjhLPvOdbfOGqoOP(jlBoNeqEykket,rafPcqsDOUeoye){ return ZBOobnK[HNvIJvEo[EWaAR(jlB" ascii
    $s13 = "function v(BuYHyUPygRpC,ukXjgvMEVVhoyy){BuYHyUPygRpC.push(ukXjgvMEVVhoyy);}" fullword ascii
    $s14 = "function EWaAR(LLtOsRtcRzt,gMFhaPmgTVduD,cljFSrMO){YiXJ=QzjDTSgfthQNbGQuE(LLtOsRtcRzt,gMFhaPmgTVduD);MZUnX=YiXJ.toString(cljFSrM" ascii
    $s15 = "function QXXALTrnhWz(oezRHSRNBKjQaX) {return isNaN(oezRHSRNBKjQaX);}" fullword ascii
    $s16 = "var o = new Array();o[0]=[];o[0][0]='d';o[0][1]='a';o[0][2]='d';o[0][3]='a';o[0][4]='46';o[0][5]='3d';o[0][6]='42';o[0][7]='14';" ascii
    $s17 = "function dvOGvFQaHsOYqSZ(spDgbCqbXUXkrpemw,EPBSMkwHnKYMoKoVNuUHlgrTxZNjGsFPbO,xVNUbqjSAeWaoOFdsMUKORWyScWqaGFMVns){eval(spDgbCqb" ascii
    $s18 = "function EWaAR(LLtOsRtcRzt,gMFhaPmgTVduD,cljFSrMO){YiXJ=QzjDTSgfthQNbGQuE(LLtOsRtcRzt,gMFhaPmgTVduD);MZUnX=YiXJ.toString(cljFSrM" ascii
    $s19 = "function nNjcrfuxkOGXyVoRcYvFpQuQtBaOSdPOJPmVkVCjhLPvOdbfOGqoOP(jlBoNeqEykket,rafPcqsDOUeoye){ return ZBOobnK[HNvIJvEo[EWaAR(jlB" ascii
    $s20 = "function HGIbdvo(fAXiYzFLjwDyJmhAAwYrQVYQnytbAeOgEFtF) {return !QXXALTrnhWz(aZtzxPnNwYEoSCF(fAXiYzFLjwDyJmhAAwYrQVYQnytbAeOgEFtF" ascii

  condition:
    uint16(0) == 0x4e48 and
    8 of them
}