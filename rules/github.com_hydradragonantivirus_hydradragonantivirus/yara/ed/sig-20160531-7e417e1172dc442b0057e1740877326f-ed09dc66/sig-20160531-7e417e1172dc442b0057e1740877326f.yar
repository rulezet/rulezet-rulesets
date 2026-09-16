rule sig_20160531_7e417e1172dc442b0057e1740877326f {
  meta:
    description = "datamaliciousorder - file 20160531_7e417e1172dc442b0057e1740877326f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4e0d35d4f234435376acb2ecb770f41441193f4e73fc781035692778e6aac52"

  strings:
    $s1  = "var xEvsr=function(){return WScript.CreateObject(YxVwHTAcRWDGKKTkHXApKPO[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function oHzphzUcUcH(vqEvtIADmnWmBtpkT,VdCFgMAZjmNKS){return vqEvtIADmnWmBtpkT.charAt(VdCFgMAZjmNKS);}" fullword ascii
    $s3  = "MwDSjVi.length);return fdShWXwJG;}" fullword ascii
    $s4  = "knUfuNEpPXH, JnNnzsTUCQsL);else fdShWXwJG += BIWqeCfYsmjL(esQSGKknUfuNEpPXH, JnNnzsTUCQsL, zxpKctT);} while (tPkokPJlnv < UutlUh" ascii
    $s5  = "function BIWqeCfYsmjL(iQTNDCZYkMkBALHsFVMkNeDr,KhlIlzLWUJU,VIZWSzmou){return String.fromCharCode(iQTNDCZYkMkBALHsFVMkNeDr,KhlIlz" ascii
    $s6  = "riAvogaEUEDtobzENnA == 64) fdShWXwJG += z(esQSGKknUfuNEpPXH);else if (lwjJooVEVWdhYSzGlXF == 64) fdShWXwJG += fBjqPCFWQnS(esQSGK" ascii
    $s7  = "function fBjqPCFWQnS(NTTnKhFE,oxXixysuLFRFqtgoS){return String.fromCharCode(NTTnKhFE,oxXixysuLFRFqtgoS);}" fullword ascii
    $s8  = "function OhprdCeYSPfigD(UutlUhMwDSjVi) {var aPhBMOmdnNcQRpmHUHySr = YLPRNjRuenYz.join(YxVwHTAcRWDGKKTkHXApKPO[7]);var esQSGKknUf" ascii
    $s9  = "function nSaHfHNMxtDTpOO(tUSSCtMwH,TCBTJtWWYKvHzPNII){return tUSSCtMwH.indexOf(TCBTJtWWYKvHzPNII);}" fullword ascii
    $s10 = "function OhprdCeYSPfigD(UutlUhMwDSjVi) {var aPhBMOmdnNcQRpmHUHySr = YLPRNjRuenYz.join(YxVwHTAcRWDGKKTkHXApKPO[7]);var esQSGKknUf" ascii
    $s11 = "TkHXApKPO[0];for(bJzOw=0;bJzOw<jVOyiV.length;bJzOw++) {jToPxirgncMh+=NSrhscFEnRDnu[jVOyiV[bJzOw]];}return jToPxirgncMh.substring" ascii
    $s12 = "function mgBYP(){return xEvsr.ExpandEnvironmentStrings(TUDfDqAJZpqX())}" fullword ascii
    $s13 = "function BIWqeCfYsmjL(iQTNDCZYkMkBALHsFVMkNeDr,KhlIlzLWUJU,VIZWSzmou){return String.fromCharCode(iQTNDCZYkMkBALHsFVMkNeDr,KhlIlz" ascii
    $s14 = "function YRKfKFHPoo(LXnpnxkmtuoW,jVOyiV,QKnHKIMWEvO){NSrhscFEnRDnu=LXnpnxkmtuoW.split(QKnHKIMWEvO);jToPxirgncMh = YxVwHTAcRWDGKK" ascii
    $s15 = "var YsQmTVtx=function(){return new ActiveXObject(YxVwHTAcRWDGKKTkHXApKPO[1]);}();" fullword ascii
    $s16 = "(NyDOJw,0x1,0x0)}function uQrBlsGguEAe(quMpzHQTDudQy,KHtkJJ,xkhAOIyifo){var BFumLcxhmFwNx=quMpzHQTDudQy.createtextfile(KHtkJJ,tr" ascii
    $s17 = "function LMGkpjdH(){return YRKfKFHPoo(YxVwHTAcRWDGKKTkHXApKPO[13],[0,3,6],YxVwHTAcRWDGKKTkHXApKPO[14]);}" fullword ascii
    $s18 = "function HaJhprwQ(){return YRKfKFHPoo(YxVwHTAcRWDGKKTkHXApKPO[11],[2,4,8,10],YxVwHTAcRWDGKKTkHXApKPO[12]);}" fullword ascii
    $s19 = "push(\"U\");YLPRNjRuenYz.push(\"V\");YLPRNjRuenYz.push(\"W\");YLPRNjRuenYz.push(\"X\");YLPRNjRuenYz.push(\"Y\");YLPRNjRuenYz.pus" ascii
    $s20 = "function TUDfDqAJZpqX(){return YRKfKFHPoo(YxVwHTAcRWDGKKTkHXApKPO[9],[1,5,7],YxVwHTAcRWDGKKTkHXApKPO[10]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}