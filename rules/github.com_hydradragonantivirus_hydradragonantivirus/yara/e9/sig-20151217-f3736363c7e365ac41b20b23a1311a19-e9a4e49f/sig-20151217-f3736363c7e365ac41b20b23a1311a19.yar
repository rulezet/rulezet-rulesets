rule sig_20151217_f3736363c7e365ac41b20b23a1311a19 {
  meta:
    description = "datamaliciousorder - file 20151217_f3736363c7e365ac41b20b23a1311a19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02e800b65e42c2c50c579637756b5f5a97f4d2a1186b467c2ebac8e15a82bec5"

  strings:
    $s1  = "th.pow(Math.cos(773), 2) - 1)); while(true) { if(YbmRzSciR[WmNuStYPlsA] > TINxD[WmNuStYPlsA].length-(-92+761)/669) { break; } if" ascii
    $s2  = "function hvseqDwGHremwLDSU(TINxD){DufZIikcvVz= '';WmNuStYPlsA=Math.round((Math.pow(Math.sin(228), 2) + Math.pow(Math.cos(228), 2" ascii
    $s3  = ") - 1));while(true){if (WmNuStYPlsA >= (1948+572)/420){break;}YbmRzSciR[WmNuStYPlsA]=Math.round((Math.pow(Math.sin(773), 2) + Ma" ascii
    $s4  = "(Math.cos(25), 2) - 1)));} YbmRzSciR[WmNuStYPlsA]++;}WmNuStYPlsA++;} return DufZIikcvVz}" fullword ascii
    $s5  = "function hvseqDwGHremwLDSU(TINxD){DufZIikcvVz= '';WmNuStYPlsA=Math.round((Math.pow(Math.sin(228), 2) + Math.pow(Math.cos(228), 2" ascii
    $s6  = "function xTBxuFtpmpNpOyZXP(xCzbnSwewW,qdSscUXjdB) {return parseInt(xCzbnSwewW,qdSscUXjdB);}" fullword ascii
    $s7  = "function RhGhZ(OXdAbpzaLWY,zBBUKEwlqhgnh,afclOpYc){JMmf=xTBxuFtpmpNpOyZXP(OXdAbpzaLWY,zBBUKEwlqhgnh);fAzOU=JMmf.toString(afclOpY" ascii
    $s8  = "function RhGhZ(OXdAbpzaLWY,zBBUKEwlqhgnh,afclOpYc){JMmf=xTBxuFtpmpNpOyZXP(OXdAbpzaLWY,zBBUKEwlqhgnh);fAzOU=JMmf.toString(afclOpY" ascii
    $s9  = "function BFgrSBs(OnQOuKgQCizStxysjIcvYTXPjndqvBFWAMpW) {return !UtdryQkhtxt(ncDdiojVEPrsSCd(OnQOuKgQCizStxysjIcvYTXPjndqvBFWAMpW" ascii
    $s10 = "var i = new Array();i[0]=[];i[0][0]='d';i[0][1]='a';i[0][2]='d';i[0][3]='a';i[0][4]='46';i[0][5]='3d';i[0][6]='42';i[0][7]='14';" ascii
    $s11 = "function UtdryQkhtxt(XKpyHxxgzHDGQQ) {return isNaN(XKpyHxxgzHDGQQ);}" fullword ascii
    $s12 = "function WBIWVwSBFNEHzJd(JAeYClLhELGicdAeb,HnuJzCRVTIaAEMpjqDiPeLVZAsiIRjDZkj,rOgsaQZrTXoFbSlNLYnXIIbXFjRjJgsJRqT){eval(JAeYClLh" ascii
    $s13 = "var i = new Array();i[0]=[];i[0][0]='d';i[0][1]='a';i[0][2]='d';i[0][3]='a';i[0][4]='46';i[0][5]='3d';i[0][6]='42';i[0][7]='14';" ascii
    $s14 = "function ncDdiojVEPrsSCd(HmqdXFXlxBifXIuQakC) {return parseFloat(HmqdXFXlxBifXIuQakC);}" fullword ascii
    $s15 = "function WBIWVwSBFNEHzJd(JAeYClLhELGicdAeb,HnuJzCRVTIaAEMpjqDiPeLVZAsiIRjDZkj,rOgsaQZrTXoFbSlNLYnXIIbXFjRjJgsJRqT){eval(JAeYClLh" ascii
    $s16 = "function DufSIjahTlDyxFeVCiYKWSudCMNmKnrFlISUKHOMiSITYSmELYPCOF(qnfGsjYzNimkw,QIAmtJJijeupBV){ return iipUnzQ[JJcLqjdN[RhGhZ(qnf" ascii
    $s17 = "function f(PgMvmQyVjBDf,cuKDYXVHmRrKid){PgMvmQyVjBDf.push(cuKDYXVHmRrKid);}" fullword ascii
    $s18 = "function DufSIjahTlDyxFeVCiYKWSudCMNmKnrFlISUKHOMiSITYSmELYPCOF(qnfGsjYzNimkw,QIAmtJJijeupBV){ return iipUnzQ[JJcLqjdN[RhGhZ(qnf" ascii
    $s19 = "c);return fAzOU;}" fullword ascii
    $s20 = "function tVvIPOHCKkoH(PUqLLcVRlMkyb) {return isFinite(PUqLLcVRlMkyb);}" fullword ascii

  condition:
    uint16(0) == 0x4a4a and
    8 of them
}