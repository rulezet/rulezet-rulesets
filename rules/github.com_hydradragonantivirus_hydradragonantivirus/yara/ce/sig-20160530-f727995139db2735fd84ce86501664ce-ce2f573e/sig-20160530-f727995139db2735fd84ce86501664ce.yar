rule sig_20160530_f727995139db2735fd84ce86501664ce {
  meta:
    description = "datamaliciousorder - file 20160530_f727995139db2735fd84ce86501664ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a36ee1d8c18c317103547247dc2fb5c50589e894136fe3d1abc494993f9f618f"

  strings:
    $s1  = "var kYBIpmqdpSyZcT=function(){return WScript.CreateObject(txperVNUTUDcvmRfhyqffP[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function WjvHDOg(VgibEmmlbuX,ojVyAJHBUvNWzUtUoOmA){return VgibEmmlbuX.charAt(ojVyAJHBUvNWzUtUoOmA);}" fullword ascii
    $s3  = "function xRsuxhtepJHTIDkP(AQfnaEpUUOoTIiEIQ,ekaZBKy,hUWCnIjfifWKIZynFG){return String.fromCharCode(AQfnaEpUUOoTIiEIQ,ekaZBKy,hUW" ascii
    $s4  = "JlaHXGIci += KJ(nSMZCjHLgrMHuz);else if (xtpqGcFll == 64) YMdqquzJlaHXGIci += FXvcTHhqGcwkzLCkEzqiR(nSMZCjHLgrMHuz, XoGhWNYywELj" ascii
    $s5  = "PaelMjzlZRvg);else YMdqquzJlaHXGIci += xRsuxhtepJHTIDkP(nSMZCjHLgrMHuz, XoGhWNYywELjPaelMjzlZRvg, lcdEqlDPo);} while (cnpxaENY <" ascii
    $s6  = "function MhqLlteqmnTnR(TwFnLeTurfv,EbRJmfGAX,GVoSZdaVSBsb){plJgNOjZM=TwFnLeTurfv.split(GVoSZdaVSBsb);BZoavWyzhXOU = txperVNUTUDc" ascii
    $s7  = "var dFiVCwh = SZMvgOhRFPn.createtextfile(kYBIpmqdpSyZcT.ExpandEnvironmentStrings(txperVNUTUDcvmRfhyqffP[3]+txperVNUTUDcvmRfhyqff" ascii
    $s8  = " mRPuobQjvlIfj.length);return YMdqquzJlaHXGIci;}" fullword ascii
    $s9  = "function MhqLlteqmnTnR(TwFnLeTurfv,EbRJmfGAX,GVoSZdaVSBsb){plJgNOjZM=TwFnLeTurfv.split(GVoSZdaVSBsb);BZoavWyzhXOU = txperVNUTUDc" ascii
    $s10 = "function ECWSSrVmCfz(){return MhqLlteqmnTnR(txperVNUTUDcvmRfhyqffP[13],[0,3,6],txperVNUTUDcvmRfhyqffP[14]);}" fullword ascii
    $s11 = "function KJ(KXJbN){return String.fromCharCode(KXJbN);}" fullword ascii
    $s12 = "function FXvcTHhqGcwkzLCkEzqiR(EfXLMOWlnprw,NWbvY){return String.fromCharCode(EfXLMOWlnprw,NWbvY);}" fullword ascii
    $s13 = "function aZsEnkOeKcZjD(){return MhqLlteqmnTnR(txperVNUTUDcvmRfhyqffP[9],[1,5,7],txperVNUTUDcvmRfhyqffP[10]);}" fullword ascii
    $s14 = "function oZcZNcnfM(qBARsKFTz,pyEqw) {var oHYCMTcrYg=[txperVNUTUDcvmRfhyqffP[15]];qBARsKFTz[oHYCMTcrYg[0]]" fullword ascii
    $s15 = "function xRsuxhtepJHTIDkP(AQfnaEpUUOoTIiEIQ,ekaZBKy,hUWCnIjfifWKIZynFG){return String.fromCharCode(AQfnaEpUUOoTIiEIQ,ekaZBKy,hUW" ascii
    $s16 = "function cekydQSIgZalm(mRPuobQjvlIfj) {var RCeAwImhaMrg = eyZXLj.join(txperVNUTUDcvmRfhyqffP[7]);var nSMZCjHLgrMHuz, XoGhWNYywEL" ascii
    $s17 = "turn BZoavWyzhXOU.substring(3,BZoavWyzhXOU.length);}" fullword ascii
    $s18 = "P[4])+String.fromCharCode(92)+txperVNUTUDcvmRfhyqffP[5],true);" fullword ascii
    $s19 = "function JNnArzOBqCrzdvJ(iXsJokxHfYUeSKsZL,dfDAqnyoaBw){return iXsJokxHfYUeSKsZL.indexOf(dfDAqnyoaBw);}" fullword ascii
    $s20 = "function tWWDcsSY(){return kYBIpmqdpSyZcT.ExpandEnvironmentStrings(aZsEnkOeKcZjD())}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}