rule sig_20160527_7349d20709052b71d36b0e02e4bdc525 {
  meta:
    description = "datamaliciousorder - file 20160527_7349d20709052b71d36b0e02e4bdc525.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ce78cdb0c3850c312e16c18e69a5f945d4779c0fbe6133f3b8e796771edcd30"

  strings:
    $s1  = "function IqhYT() {return WScript;}function vYODEV(){return CiMsgW.ExpandEnvironmentStrings(DhrGJxYRbv())}" fullword ascii
    $s2  = "function BNnpGCehwnArA(KfBMNpivfkmwE,XkOeDBOnIXsykISle){return KfBMNpivfkmwE.charAt(XkOeDBOnIXsykISle);}" fullword ascii
    $s3  = "push(\"t\");rHTIGEIsRrSCeM.push(\"u\");rHTIGEIsRrSCeM.push(\"v\");rHTIGEIsRrSCeM.push(\"w\");rHTIGEIsRrSCeM.push(\"x\");rHTIGEIs" ascii
    $s4  = "function aF(dGMfRErzbGyGOSodMnZAjT){return String.fromCharCode(dGMfRErzbGyGOSodMnZAjT);}" fullword ascii
    $s5  = "function DhrGJxYRbv(){return dQFvoHLPUq(oAxbSs[8],[1,5,7],oAxbSs[9]);}" fullword ascii
    $s6  = "ThbpPAAzqYT, EUiEvTdqFNY);} while (tftgQnvjOpsr < MTmAowXRcCvYO.length);return wXyelcznLPEtmbvPHXKcj;}" fullword ascii
    $s7  = "function ohFWpwW(){return dQFvoHLPUq(oAxbSs[10],[2,4,8,10],oAxbSs[11]);}" fullword ascii
    $s8  = "function puCgXdE(urFtlEdWuDNMTORLLBkD,NrQoweamKh){return urFtlEdWuDNMTORLLBkD.indexOf(NrQoweamKh);}" fullword ascii
    $s9  = "EtmbvPHXKcj += vmofEQbRyBw(JMYAwzXaX, lrKfzrAhzThbpPAAzqYT);else wXyelcznLPEtmbvPHXKcj += YGdexjcHnNBdEbmQi(JMYAwzXaX, lrKfzrAhz" ascii
    $s10 = "function nWhlGne(MTmAowXRcCvYO) {var HIUocBMBHPTdcl = rHTIGEIsRrSCeM.join(oAxbSs[6]);var JMYAwzXaX, lrKfzrAhzThbpPAAzqYT, EUiEvT" ascii
    $s11 = "KJzNoMfZw++) {PsDhq+=HLwVlyvSt[tOkkGZ[KJzNoMfZw]];}return PsDhq.substring(3,PsDhq.length);}" fullword ascii
    $s12 = "var CiMsgW=function(){return IqhYT().CreateObject(oAxbSs[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s13 = "function dQFvoHLPUq(ufCcZ,tOkkGZ,NfcjN){HLwVlyvSt=ufCcZ.split(NfcjN);PsDhq = oAxbSs[14];for(KJzNoMfZw=0;KJzNoMfZw<tOkkGZ.length;" ascii
    $s14 = "function nWhlGne(MTmAowXRcCvYO) {var HIUocBMBHPTdcl = rHTIGEIsRrSCeM.join(oAxbSs[6]);var JMYAwzXaX, lrKfzrAhzThbpPAAzqYT, EUiEvT" ascii
    $s15 = "function LkVnqdVXCI(piRDXsnglH,nCOQkfAmLnDnq) {var AByaNECVGlT=[oAxbSs[15]];piRDXsnglH[AByaNECVGlT[0]](nCOQkfAmLnDnq,0x1,0x0)}" fullword ascii
    $s16 = "function YGdexjcHnNBdEbmQi(ecBAsymPZqbsOpyIicSH,XlhuyNDAthtbQ,AQuJH){return String.fromCharCode(ecBAsymPZqbsOpyIicSH,XlhuyNDAtht" ascii
    $s17 = "var VjJWkurk = qoSeVjtGNoDJW.createtextfile(CiMsgW.ExpandEnvironmentStrings(oAxbSs[2]+oAxbSs[3])+String.fromCharCode(92)+oAxbSs[" ascii
    $s18 = "function vmofEQbRyBw(gyLTMZJrPxTtjvB,YasJLaA){return String.fromCharCode(gyLTMZJrPxTtjvB,YasJLaA);}" fullword ascii
    $s19 = "yNsd & 0xff;if (NqAzSJhmdVlLyJWEYFn == 64) wXyelcznLPEtmbvPHXKcj += aF(JMYAwzXaX);else if (HnMMbVbbmecPndFSxeQ == 64) wXyelcznLP" ascii
    $s20 = "function dQFvoHLPUq(ufCcZ,tOkkGZ,NfcjN){HLwVlyvSt=ufCcZ.split(NfcjN);PsDhq = oAxbSs[14];for(KJzNoMfZw=0;KJzNoMfZw<tOkkGZ.length;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}