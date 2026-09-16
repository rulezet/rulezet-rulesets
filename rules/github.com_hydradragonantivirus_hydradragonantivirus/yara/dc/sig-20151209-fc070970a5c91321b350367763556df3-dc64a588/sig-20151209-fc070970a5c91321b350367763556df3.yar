rule sig_20151209_fc070970a5c91321b350367763556df3 {
  meta:
    description = "datamaliciousorder - file 20151209_fc070970a5c91321b350367763556df3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4c8787cf0456e449e81b545297f0019a482f4d0d53738d524e6a1faf47003e1"

  strings:
    $s1  = "function HSESoiT(tzNwHWLASSFVpnCbJJNfZAvimtMPsOodynCF) {return !isNaN(parseFloat(tzNwHWLASSFVpnCbJJNfZAvimtMPsOodynCF)) && isFin" ascii
    $s2  = "function HSESoiT(tzNwHWLASSFVpnCbJJNfZAvimtMPsOodynCF) {return !isNaN(parseFloat(tzNwHWLASSFVpnCbJJNfZAvimtMPsOodynCF)) && isFin" ascii
    $s3  = "+;}} return ThWOxhrZtMs}" fullword ascii
    $s4  = "function xTuEO(ZegCLsOFEGT,ujAbSktXYsxot,hgcdQiZR){YrPP=parseInt(ZegCLsOFEGT,ujAbSktXYsxot);mgSbD=YrPP.toString(hgcdQiZR);return" ascii
    $s5  = "function xTuEO(ZegCLsOFEGT,ujAbSktXYsxot,hgcdQiZR){YrPP=parseInt(ZegCLsOFEGT,ujAbSktXYsxot);mgSbD=YrPP.toString(hgcdQiZR);return" ascii
    $s6  = "function TGtbUkSTJgMhJpslILzvMXvkkRhgVIUOomcDohlLAGErhmTIDjcOxS(yBrOEXftHNEGW,zxNNmAqzEDikIM){ return StyTk[xTuEO(yBrOEXftHNEGW[" ascii
    $s7  = "xKxAylcS[wkaeHbpTxUc]=(-373+373)/932; while(true) { if(mxKxAylcS[wkaeHbpTxUc] > SXfUd[wkaeHbpTxUc].length-(256+609)/865) { break" ascii
    $s8  = " mgSbD;}function YxLvzItRSHUUZDz(KYLxXZNUNwBgvPaub){eval(KYLxXZNUNwBgvPaub)}" fullword ascii
    $s9  = "function TApWHSIyJYrsfqkuR(SXfUd){ThWOxhrZtMs= '';for(wkaeHbpTxUc=(-264+264)/557; wkaeHbpTxUc < (752+648)/700; wkaeHbpTxUc++) {m" ascii
    $s10 = "function TApWHSIyJYrsfqkuR(SXfUd){ThWOxhrZtMs= '';for(wkaeHbpTxUc=(-264+264)/557; wkaeHbpTxUc < (752+648)/700; wkaeHbpTxUc++) {m" ascii
    $s11 = "function KcPmWtTfgpB(ZmhspFfn,dBiUXB){return ZmhspFfn.split(dBiUXB)}" fullword ascii
    $s12 = "function TGtbUkSTJgMhJpslILzvMXvkkRhgVIUOomcDohlLAGErhmTIDjcOxS(yBrOEXftHNEGW,zxNNmAqzEDikIM){ return StyTk[xTuEO(yBrOEXftHNEGW[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}