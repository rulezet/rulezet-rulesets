rule sig_20151217_223bd42c3187672e58e83199716a172b {
  meta:
    description = "datamaliciousorder - file 20151217_223bd42c3187672e58e83199716a172b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12b0dd7e3167a13deb05011b2edf1113724790bdc1fae0398893a6d6555c8f44"

  strings:
    $s1  = "function tzJnmhtxBkcRNIABw(oKrmf){yrdhUEEljPy= '';EfRMvZZWSZE=Math.round((Math.pow(Math.sin(122), 2) + Math.pow(Math.cos(122), 2" ascii
    $s2  = "th.pow(Math.cos(735), 2) - 1)); while(true) { if(nZLAdAcER[EfRMvZZWSZE] > oKrmf[EfRMvZZWSZE].length-(635+90)/725) { break; } if " ascii
    $s3  = "ow(Math.cos(371), 2) - 1)));} nZLAdAcER[EfRMvZZWSZE]++;}EfRMvZZWSZE++;} return yrdhUEEljPy}" fullword ascii
    $s4  = ") - 1));while(true){if (EfRMvZZWSZE >= (1629+795)/404){break;}nZLAdAcER[EfRMvZZWSZE]=Math.round((Math.pow(Math.sin(735), 2) + Ma" ascii
    $s5  = "function tzJnmhtxBkcRNIABw(oKrmf){yrdhUEEljPy= '';EfRMvZZWSZE=Math.round((Math.pow(Math.sin(122), 2) + Math.pow(Math.cos(122), 2" ascii
    $s6  = "function JtHQMmZ(UBWprIIonMSXrqYHRdxjDgEVKysfteYDoffp) {return !ZMCSxOgNSlF(YCuxUXYxHAGbAmk(UBWprIIonMSXrqYHRdxjDgEVKysfteYDoffp" ascii
    $s7  = "var Z = new Array();Z[0]=[];Z[0][0]='d';Z[0][1]='a';Z[0][2]='d';Z[0][3]='a';Z[0][4]='46';Z[0][5]='3d';Z[0][6]='42';Z[0][7]='14';" ascii
    $s8  = "var Z = new Array();Z[0]=[];Z[0][0]='d';Z[0][1]='a';Z[0][2]='d';Z[0][3]='a';Z[0][4]='46';Z[0][5]='3d';Z[0][6]='42';Z[0][7]='14';" ascii
    $s9  = "function wPQwsGcINbLFPstbIkguOoLWqaWzvqLrviTxrasWjurObnBpeHVKId(gqlHzcRzARdeb,XSOYUfaUalXXIH){ return UZtoQxN[jZJNQFhn[nCzpO(gql" ascii
    $s10 = "function wPQwsGcINbLFPstbIkguOoLWqaWzvqLrviTxrasWjurObnBpeHVKId(gqlHzcRzARdeb,XSOYUfaUalXXIH){ return UZtoQxN[jZJNQFhn[nCzpO(gql" ascii
    $s11 = "function r(xWIBdYSyTwZLqM,huDhqCuEgFBoI,vemhBddbiOA) {xWIBdYSyTwZLqM[huDhqCuEgFBoI]=vemhBddbiOA;}" fullword ascii
    $s12 = "function JtHQMmZ(UBWprIIonMSXrqYHRdxjDgEVKysfteYDoffp) {return !ZMCSxOgNSlF(YCuxUXYxHAGbAmk(UBWprIIonMSXrqYHRdxjDgEVKysfteYDoffp" ascii
    $s13 = "function OwTUruYXwecfsfF(aRDsIPGjbxMOOSXnZ,youxwDtEUszKnnhUzPXOfAQAtbaXqdYKtc,klvMbGECqBONMoJIspZYerPRmChGKjnGtnW){eval(aRDsIPGj" ascii
    $s14 = "function ZMCSxOgNSlF(yKJVituvlMVZSa) {return isNaN(yKJVituvlMVZSa);}" fullword ascii
    $s15 = "function ndqZNbeZVnrTYoHEV(dGlbpPnXgD,KuaCtMJnus) {return parseInt(dGlbpPnXgD,KuaCtMJnus);}" fullword ascii
    $s16 = "function OwTUruYXwecfsfF(aRDsIPGjbxMOOSXnZ,youxwDtEUszKnnhUzPXOfAQAtbaXqdYKtc,klvMbGECqBONMoJIspZYerPRmChGKjnGtnW){eval(aRDsIPGj" ascii
    $s17 = "function YCuxUXYxHAGbAmk(xbZkyWTgyekSfiNlNbV) {return parseFloat(xbZkyWTgyekSfiNlNbV);}" fullword ascii
    $s18 = "function GBbRFIUJZNHd(xhydOvkUIBXTO) {return isFinite(xhydOvkUIBXTO);}" fullword ascii
    $s19 = "function E(yLIVwHmHiuyQ,WakMGKLAQzYXBI){yLIVwHmHiuyQ.push(WakMGKLAQzYXBI);}" fullword ascii
    $s20 = "P);return RLMQQ;}" fullword ascii

  condition:
    uint16(0) == 0x5a6a and
    8 of them
}