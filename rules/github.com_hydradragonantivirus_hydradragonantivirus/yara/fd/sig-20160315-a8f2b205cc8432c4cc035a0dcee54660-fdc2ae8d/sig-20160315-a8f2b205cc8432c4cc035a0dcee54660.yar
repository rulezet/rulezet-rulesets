rule sig_20160315_a8f2b205cc8432c4cc035a0dcee54660 {
  meta:
    description = "datamaliciousorder - file 20160315_a8f2b205cc8432c4cc035a0dcee54660.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c335e86e814dc9a9475ff756a0b1e0995f61276594db2300fe3e1a33478bc25a"

  strings:
    $s1 = "function kHw(ZDMWAu){WshShell[cnB + pQmrnbyQIEvrso](ZDMWAu, 0, 0);}" fullword ascii
    $s2 = "while (NMPpt.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "zyqMcnii + eYpPUzDOPtX + PScKtcxotzuNczX + fKVRGfxWt + UWmCURLzj + MYASUIVwMvtAl, false);" fullword ascii
    $s4 = "var MrMAbOX = new Date();" fullword ascii
    $s5 = "function VpJcjS(n){return sXjFCa + qsKgTutOp + pbybiP + KgFDdFYPDTRL + RCBZpvnFrzRas + uqtCzGo + gzEI + BkKF;}" fullword ascii
    $s6 = "NMPpt[XSsHIZGGBPA + bQKAbdBw](PhDBZL, VBNJQMrAOtciYR + MWtUmS + OLnJK + pEdbgaXUjurmFJj + eKCOV + NvCLAzrX + yvgKlUmxSGrHO + Jgd" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}