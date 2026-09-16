rule sig_20160526_42a299b53166f5987b55d899b4e7c409 {
  meta:
    description = "datamaliciousorder - file 20160526_42a299b53166f5987b55d899b4e7c409.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "caad9d3e6faae5f1f993198afcaafe40631045c6a08726f6611b33ee7f8cb65c"

  strings:
    $s1  = "function xKjTMrzD(BVflhhjlTsXfZ) {var CtYYhw = gbCodFkGRHU.join(JMSRkNg[0]);var oPDnaIbYMaGavAAdH, FlYPXNTGtzWdiECYSyza, CwgJzkK" ascii
    $s2  = "H);else if (DkPdkSPQXe == (507 + Math.round((Math.pow(Math.sin(493), 2) + Math.pow(Math.cos(493), 2) - 1))-443)) hFpUsyV += OPPl" ascii
    $s3  = "function gtCGOYoUXpRClcTOnsRTR(pEZUxVxlMIb,HHCrxBDMRRM){return pEZUxVxlMIb.charAt(HHCrxBDMRRM);}" fullword ascii
    $s4  = "function XFdoOgUAfkoXcrm(ifXOlRlsWmeHZufSKa,KIiyHWffzQvcwHqBYzaaY){return ifXOlRlsWmeHZufSKa.indexOf(KIiyHWffzQvcwHqBYzaaY);}" fullword ascii
    $s5  = "function KuaKw(ohUNjFJEL,gGSKoCkCCDuwpuIBLgAkk,uqNYDjiPtqteAFCjunKnbWDT){return String.fromCharCode(ohUNjFJEL,gGSKoCkCCDuwpuIBLg" ascii
    $s6  = "tNxq);} while (lvasqLKgQbr < BVflhhjlTsXfZ.length);return hFpUsyV;}" fullword ascii
    $s7  = "function OPPlWWGMOMTRMHfY(KXVaOzKZWMQFIgQ,CdkyXwxQMtnZmJeWwqinFXH){return String.fromCharCode(KXVaOzKZWMQFIgQ,CdkyXwxQMtnZmJeWwq" ascii
    $s8  = "function OPPlWWGMOMTRMHfY(KXVaOzKZWMQFIgQ,CdkyXwxQMtnZmJeWwqinFXH){return String.fromCharCode(KXVaOzKZWMQFIgQ,CdkyXwxQMtnZmJeWwq" ascii
    $s9  = "function P(WBftayBDwhCO){return String.fromCharCode(WBftayBDwhCO);}" fullword ascii
    $s10 = "function KuaKw(ohUNjFJEL,gGSKoCkCCDuwpuIBLgAkk,uqNYDjiPtqteAFCjunKnbWDT){return String.fromCharCode(ohUNjFJEL,gGSKoCkCCDuwpuIBLg" ascii
    $s11 = "function xKjTMrzD(BVflhhjlTsXfZ) {var CtYYhw = gbCodFkGRHU.join(JMSRkNg[0]);var oPDnaIbYMaGavAAdH, FlYPXNTGtzWdiECYSyza, CwgJzkK" ascii
    $s12 = "WWGMOMTRMHfY(oPDnaIbYMaGavAAdH, FlYPXNTGtzWdiECYSyza);else hFpUsyV += KuaKw(oPDnaIbYMaGavAAdH, FlYPXNTGtzWdiECYSyza, CwgJzkKiEsO" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}