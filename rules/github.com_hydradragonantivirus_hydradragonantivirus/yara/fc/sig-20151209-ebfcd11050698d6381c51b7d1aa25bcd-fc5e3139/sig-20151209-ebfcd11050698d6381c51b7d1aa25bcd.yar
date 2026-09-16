rule sig_20151209_ebfcd11050698d6381c51b7d1aa25bcd {
  meta:
    description = "datamaliciousorder - file 20151209_ebfcd11050698d6381c51b7d1aa25bcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "546fc61e8de74d0588582fb3f9968df49516d9f729e5a7b832ff92a0b15feeb2"

  strings:
    $s1  = "function PbdQiFM(wtOTbupFnlkOLOAHMFqTLmCfIktnxWgTcdzx) {return !isNaN(parseFloat(wtOTbupFnlkOLOAHMFqTLmCfIktnxWgTcdzx)) && isFin" ascii
    $s2  = "function PbdQiFM(wtOTbupFnlkOLOAHMFqTLmCfIktnxWgTcdzx) {return !isNaN(parseFloat(wtOTbupFnlkOLOAHMFqTLmCfIktnxWgTcdzx)) && isFin" ascii
    $s3  = "function FkjVfBnmnrqeluwRn(FPtoa){wfjSnijNmQb= '';for(TFKDnvoAxmx=(-937+937)/965; TFKDnvoAxmx < (-339+993)/327; TFKDnvoAxmx++) {" ascii
    $s4  = "function aTOvTLRBzyZpgKOHEzoywtYfSHVjahvEgNboRoplXRrHOimIxaWZhP(AwULVhIWqIgCO,PCKoDRKRhtzqdo){ return vGBkQ[nSaYH(AwULVhIWqIgCO[" ascii
    $s5  = " NfGbJ;}function sqNLKZCeYfKTtLs(hJeKcINXQbRiJjNTu){eval(hJeKcINXQbRiJjNTu)}" fullword ascii
    $s6  = "function nSaYH(MIgpkJNwlaB,tSQtopQCUiQmT,XzEssjHg){fSCt=parseInt(MIgpkJNwlaB,tSQtopQCUiQmT);NfGbJ=fSCt.toString(XzEssjHg);return" ascii
    $s7  = "vepzWuvxk[TFKDnvoAxmx]=(-675+675)/571; while(true) { if(vepzWuvxk[TFKDnvoAxmx] > FPtoa[TFKDnvoAxmx].length-(383+561)/944) { brea" ascii
    $s8  = "function FkjVfBnmnrqeluwRn(FPtoa){wfjSnijNmQb= '';for(TFKDnvoAxmx=(-937+937)/965; TFKDnvoAxmx < (-339+993)/327; TFKDnvoAxmx++) {" ascii
    $s9  = "function aTOvTLRBzyZpgKOHEzoywtYfSHVjahvEgNboRoplXRrHOimIxaWZhP(AwULVhIWqIgCO,PCKoDRKRhtzqdo){ return vGBkQ[nSaYH(AwULVhIWqIgCO[" ascii
    $s10 = "function keWbrCiSSqf(vpiEKVtL,yBnmra){return vpiEKVtL.split(yBnmra)}" fullword ascii
    $s11 = "++;}} return wfjSnijNmQb}" fullword ascii
    $s12 = "function nSaYH(MIgpkJNwlaB,tSQtopQCUiQmT,XzEssjHg){fSCt=parseInt(MIgpkJNwlaB,tSQtopQCUiQmT);NfGbJ=fSCt.toString(XzEssjHg);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}