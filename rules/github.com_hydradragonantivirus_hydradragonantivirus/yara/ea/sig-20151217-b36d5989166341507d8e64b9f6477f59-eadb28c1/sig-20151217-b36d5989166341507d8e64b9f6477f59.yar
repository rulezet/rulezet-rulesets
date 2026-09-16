rule sig_20151217_b36d5989166341507d8e64b9f6477f59 {
  meta:
    description = "datamaliciousorder - file 20151217_b36d5989166341507d8e64b9f6477f59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfb5b960af278d6d978213c6a2c558fe6009f080a6a780e148e5fdec25119d6a"

  strings:
    $s1  = "h.cos(501), 2) - 1)));} KZOixukqa[aEbMDksiGRE]++;}aEbMDksiGRE++;} return sPoJwsfVdtI}" fullword ascii
    $s2  = ") - 1));while(true){if (aEbMDksiGRE >= (1873+473)/391){break;}KZOixukqa[aEbMDksiGRE]=Math.round((Math.pow(Math.sin(972), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(972), 2) - 1)); while(true) { if(KZOixukqa[aEbMDksiGRE] > Ayqam[aEbMDksiGRE].length-(127+0)/127) { break; } if (" ascii
    $s4  = "function BRGfpfFvkBLJYXqMY(Ayqam){sPoJwsfVdtI= '';aEbMDksiGRE=Math.round((Math.pow(Math.sin(358), 2) + Math.pow(Math.cos(358), 2" ascii
    $s5  = "function BRGfpfFvkBLJYXqMY(Ayqam){sPoJwsfVdtI= '';aEbMDksiGRE=Math.round((Math.pow(Math.sin(358), 2) + Math.pow(Math.cos(358), 2" ascii
    $s6  = "function qOJzjcgzhnEQbfHpt(jVzuCiRnPD,iOEarIRcOh) {return parseInt(jVzuCiRnPD,iOEarIRcOh);}" fullword ascii
    $s7  = "function XKdBqPp(MnBDHgutunUIDjhSMMDiahWcLNZUbwiKthNB) {return !MOHpSQrdRAn(xpBCncXFgEemwDV(MnBDHgutunUIDjhSMMDiahWcLNZUbwiKthNB" ascii
    $s8  = "var E = new Array();E[0]=[];E[0][0]='d';E[0][1]='a';E[0][2]='d';E[0][3]='a';E[0][4]='46';E[0][5]='3d';E[0][6]='42';E[0][7]='14';" ascii
    $s9  = "function VqYfm(ecGzyzpqFes,vIFuPShrJlRPq,SBHlKkNy){Jeas=qOJzjcgzhnEQbfHpt(ecGzyzpqFes,vIFuPShrJlRPq);oxdMN=Jeas.toString(SBHlKkN" ascii
    $s10 = "y);return oxdMN;}" fullword ascii
    $s11 = "function WWBoFmBcgcnuYHM(bguaESdNMbufTRIJy,exbjvkxHTbaAlhvVKgXpafNcKXaIJjlLMJ,DACteeEehFXKYwPcfnkEmwkKTMIdSSOzZDv){eval(bguaESdN" ascii
    $s12 = "function XKdBqPp(MnBDHgutunUIDjhSMMDiahWcLNZUbwiKthNB) {return !MOHpSQrdRAn(xpBCncXFgEemwDV(MnBDHgutunUIDjhSMMDiahWcLNZUbwiKthNB" ascii
    $s13 = "function mlJBkfLHIAob(RRoKRinfFXaAW) {return isFinite(RRoKRinfFXaAW);}" fullword ascii
    $s14 = "function WWBoFmBcgcnuYHM(bguaESdNMbufTRIJy,exbjvkxHTbaAlhvVKgXpafNcKXaIJjlLMJ,DACteeEehFXKYwPcfnkEmwkKTMIdSSOzZDv){eval(bguaESdN" ascii
    $s15 = "function VqYfm(ecGzyzpqFes,vIFuPShrJlRPq,SBHlKkNy){Jeas=qOJzjcgzhnEQbfHpt(ecGzyzpqFes,vIFuPShrJlRPq);oxdMN=Jeas.toString(SBHlKkN" ascii
    $s16 = "function w(pakvHPaQIZhqsx,bhwJErlWctPbd,uTwaLgcQWFN) {pakvHPaQIZhqsx[bhwJErlWctPbd]=uTwaLgcQWFN;}" fullword ascii
    $s17 = "function V(WuNihniMsBtX,zXuUScGSevtpBK){WuNihniMsBtX.push(zXuUScGSevtpBK);}" fullword ascii
    $s18 = "function xpBCncXFgEemwDV(GGcyhFwNuBYdEnCWxMe) {return parseFloat(GGcyhFwNuBYdEnCWxMe);}" fullword ascii
    $s19 = "var E = new Array();E[0]=[];E[0][0]='d';E[0][1]='a';E[0][2]='d';E[0][3]='a';E[0][4]='46';E[0][5]='3d';E[0][6]='42';E[0][7]='14';" ascii
    $s20 = "function MOHpSQrdRAn(EBqfyuipWwciQa) {return isNaN(EBqfyuipWwciQa);}" fullword ascii

  condition:
    uint16(0) == 0x6744 and
    8 of them
}