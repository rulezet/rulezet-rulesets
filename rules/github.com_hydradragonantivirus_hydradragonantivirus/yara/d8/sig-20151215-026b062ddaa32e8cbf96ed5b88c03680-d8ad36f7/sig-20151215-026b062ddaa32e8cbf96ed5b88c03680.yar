rule sig_20151215_026b062ddaa32e8cbf96ed5b88c03680 {
  meta:
    description = "datamaliciousorder - file 20151215_026b062ddaa32e8cbf96ed5b88c03680.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6e62621e3fdc22e9b5e3395f90bdd3619781f48fa659273b70873b83d97d4b7"

  strings:
    $s1  = "ath.pow(Math.cos(526), 2) - 1)); while(true) { if(XinZvmvKb[djdzyzaGpgJ] > swOfv[djdzyzaGpgJ].length-(-299+330)/31) { break; } i" ascii
    $s2  = ".pow(Math.cos(879), 2) - 1)));} XinZvmvKb[djdzyzaGpgJ]++;}} return LrafQpuSgAh}" fullword ascii
    $s3  = "function MzgGrgGnBXVLfkwix(swOfv){LrafQpuSgAh= j[1808];for(djdzyzaGpgJ=Math.round((Math.pow(Math.sin(958), 2) + Math.pow(Math.co" ascii
    $s4  = "function MzgGrgGnBXVLfkwix(swOfv){LrafQpuSgAh= j[1808];for(djdzyzaGpgJ=Math.round((Math.pow(Math.sin(958), 2) + Math.pow(Math.co" ascii
    $s5  = "RqKUOrvdbxymgADOQHdWnGIsLlAsrFYCnJvI([swOfv[djdzyzaGpgJ][XinZvmvKb[djdzyzaGpgJ]]], Math.round((Math.pow(Math.sin(879), 2) + Math" ascii
    $s6  = "function G(wFyCRHCCIgmd,NXxCtdedsjkMgE){wFyCRHCCIgmd.push(NXxCtdedsjkMgE);}function Q6(RdXnxIAwGdOrWKgE){if(DibtHIM(RdXnxIAwGdOr" ascii
    $s7  = "WKgE)) {return (String.fromCharCode(RdXnxIAwGdOrWKgE) + String.fromCharCode((25154+307)/621));}}" fullword ascii
    $s8  = "function DibtHIM(ASHXkiPrMlhSlOPxNwnckTneRqBaMsRoCnKI) {return !isNaN(parseFloat(ASHXkiPrMlhSlOPxNwnckTneRqBaMsRoCnKI)) && isFin" ascii
    $s9  = "function DibtHIM(ASHXkiPrMlhSlOPxNwnckTneRqBaMsRoCnKI) {return !isNaN(parseFloat(ASHXkiPrMlhSlOPxNwnckTneRqBaMsRoCnKI)) && isFin" ascii
    $s10 = "var j=new Array();" fullword ascii
    $s11 = "function prKxSYtOqdV(fvvCiQTc,HqIaLS){return fvvCiQTc.split(HqIaLS)}" fullword ascii
    $s12 = "function G(wFyCRHCCIgmd,NXxCtdedsjkMgE){wFyCRHCCIgmd.push(NXxCtdedsjkMgE);}function Q6(RdXnxIAwGdOrWKgE){if(DibtHIM(RdXnxIAwGdOr" ascii
    $s13 = "function ZlCVB(XobREtYFtSk,gprslVMmFxhXr,AcsLwzHR){ogJi=parseInt(XobREtYFtSk,gprslVMmFxhXr);CzkqG=ogJi.toString(AcsLwzHR);return" ascii
    $s14 = " CzkqG;}function EKyMVCYDBzoPjWl(MIoWfpljiKeQTChYF,moulpKJfRpFSBLXXQwnoPQkAAysXnqXBmj,hdbgCPLSfeTqPlutzEzyUWSVzYkQwabQrau){eval(" ascii
    $s15 = "function hybIbZHWuKeVelyTVgRqKUOrvdbxymgADOQHdWnGIsLlAsrFYCnJvI(TiWeDamCTfBJP,CiYXUmaLlQifJB){ return cSJaRhs[RjGeakFd[ZlCVB(TiW" ascii
    $s16 = "function hybIbZHWuKeVelyTVgRqKUOrvdbxymgADOQHdWnGIsLlAsrFYCnJvI(TiWeDamCTfBJP,CiYXUmaLlQifJB){ return cSJaRhs[RjGeakFd[ZlCVB(TiW" ascii
    $s17 = "function EKyMVCYDBzoPjWl(MIoWfpljiKeQTChYF){eval(MIoWfpljiKeQTChYF)}" fullword ascii
    $s18 = "function ZlCVB(XobREtYFtSk,gprslVMmFxhXr,AcsLwzHR){ogJi=parseInt(XobREtYFtSk,gprslVMmFxhXr);CzkqG=ogJi.toString(AcsLwzHR);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}