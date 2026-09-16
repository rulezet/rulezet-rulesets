rule sig_20151217_47ab40decd201c133d11b2b3f1da83d6 {
  meta:
    description = "datamaliciousorder - file 20151217_47ab40decd201c133d11b2b3f1da83d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a90fd2662e9898728e7ec5e86c16ab66bf7d010a2bcd827d2c039bd6de614e5f"

  strings:
    $s1  = ") - 1));while(true){if (rLsOeEkFLwe >= (2292+498)/465){break;}SJwCIGsEO[rLsOeEkFLwe]=Math.round((Math.pow(Math.sin(773), 2) + Ma" ascii
    $s2  = "(Math.cos(517), 2) - 1)));} SJwCIGsEO[rLsOeEkFLwe]++;}rLsOeEkFLwe++;} return UPcpESOfqeM}" fullword ascii
    $s3  = "th.pow(Math.cos(773), 2) - 1)); while(true) { if(SJwCIGsEO[rLsOeEkFLwe] > fsykB[rLsOeEkFLwe].length-(765+63)/828) { break; } if " ascii
    $s4  = "function KxKqeOkouIFcnjUHz(fsykB){UPcpESOfqeM= '';rLsOeEkFLwe=Math.round((Math.pow(Math.sin(155), 2) + Math.pow(Math.cos(155), 2" ascii
    $s5  = "function KxKqeOkouIFcnjUHz(fsykB){UPcpESOfqeM= '';rLsOeEkFLwe=Math.round((Math.pow(Math.sin(155), 2) + Math.pow(Math.cos(155), 2" ascii
    $s6  = "function GIWkhSv(wByzBNmKbMuisXxKWZEzCLCMQvkwzMnqJucs) {return !bAyHnylMeov(ViCtLnrhkFMyjUy(wByzBNmKbMuisXxKWZEzCLCMQvkwzMnqJucs" ascii
    $s7  = "function t(xGOMyOcmdQYYIG,KVfEsgRPwAIJS,fAJtnrDudSh) {xGOMyOcmdQYYIG[KVfEsgRPwAIJS]=fAJtnrDudSh;}" fullword ascii
    $s8  = "var Q = new Array();Q[0]=[];Q[0][0]='d';Q[0][1]='a';Q[0][2]='d';Q[0][3]='a';Q[0][4]='46';Q[0][5]='3d';Q[0][6]='42';Q[0][7]='14';" ascii
    $s9  = "function GIWkhSv(wByzBNmKbMuisXxKWZEzCLCMQvkwzMnqJucs) {return !bAyHnylMeov(ViCtLnrhkFMyjUy(wByzBNmKbMuisXxKWZEzCLCMQvkwzMnqJucs" ascii
    $s10 = "function bAyHnylMeov(qoOLYKUWbeswwc) {return isNaN(qoOLYKUWbeswwc);}" fullword ascii
    $s11 = "function kicHFVPSclIStCB(FvyVAdqKSajAKiDIA,xOxdPAUhhatXmyfHkJiqgOWJrXlLWnDTmV,iXoRmKMmtKoxLFrHJQqhLrBIueesndawvQx){eval(FvyVAdqK" ascii
    $s12 = "function hkESUADdJMWivMUjG(CKqCsZqkvG,YzGPbEodQm) {return parseInt(CKqCsZqkvG,YzGPbEodQm);}" fullword ascii
    $s13 = "D);return bCTau;}" fullword ascii
    $s14 = "function XRlpaLgOsexJ(enXDtszAqTFPI) {return isFinite(enXDtszAqTFPI);}" fullword ascii
    $s15 = "function ViCtLnrhkFMyjUy(sOkvYCDevlgdLyWzeWl) {return parseFloat(sOkvYCDevlgdLyWzeWl);}" fullword ascii
    $s16 = "var Q = new Array();Q[0]=[];Q[0][0]='d';Q[0][1]='a';Q[0][2]='d';Q[0][3]='a';Q[0][4]='46';Q[0][5]='3d';Q[0][6]='42';Q[0][7]='14';" ascii
    $s17 = "function eBkllTrZrOVxuPjWPgEehTInxTHlijfzFYmIXSBETQiRPvVwfRJJCZ(fDFAWdSwfaADI,QPcHjfLkLGEoAE){ return yrttBTK[PQfYWvxS[TZDoR(fDF" ascii
    $s18 = "function TZDoR(aXOjTFuSNul,EfZulWxtYpwyR,nbejRhbD){zFIP=hkESUADdJMWivMUjG(aXOjTFuSNul,EfZulWxtYpwyR);bCTau=zFIP.toString(nbejRhb" ascii
    $s19 = "function h(IKrARBKxPyEo,oMLWPvCVunZvRp){IKrARBKxPyEo.push(oMLWPvCVunZvRp);}" fullword ascii
    $s20 = "function eBkllTrZrOVxuPjWPgEehTInxTHlijfzFYmIXSBETQiRPvVwfRJJCZ(fDFAWdSwfaADI,QPcHjfLkLGEoAE){ return yrttBTK[PQfYWvxS[TZDoR(fDF" ascii

  condition:
    uint16(0) == 0x5150 and
    8 of them
}