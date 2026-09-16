rule sig_20160526_d9c2cb71727ede04a1ed444c586aec66 {
  meta:
    description = "datamaliciousorder - file 20160526_d9c2cb71727ede04a1ed444c586aec66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76dee4b3f9b380703520665737a12169e3dda4b0a19e34c068e6a0f232d12221"

  strings:
    $s1  = "function EQvHVEuRxSmudD(kQchbIHWWkeaU) {var GsneQNePPAaPar = xgofAjtivPmn.join(lDTszjRNbfYGYgkagJElDfk[0]);var HdejLMcJrtIIFzjKp" ascii
    $s2  = "h.pow(Math.cos(323), 2) - 1))-665)) CBXemuKIsjmU += tHzwGuKtgqJCpKLg(HdejLMcJrtIIFzjKpwC, EBLMlNWBaNrDoGLliTK);else CBXemuKIsjmU" ascii
    $s3  = "- 1))-400)) CBXemuKIsjmU += vY(HdejLMcJrtIIFzjKpwC);else if (DKUZCMBNtSBT == (729 + Math.round((Math.pow(Math.sin(323), 2) + Mat" ascii
    $s4  = "function HxmRuBKJgKHfFDdpWm(PlWpvy,idigfoKRETTFDEuNJSfqhXoU){return PlWpvy.charAt(idigfoKRETTFDEuNJSfqhXoU);}" fullword ascii
    $s5  = "function tGUBohpJaeVVni(FkuKNafEsrR,AbHXbYmzm,uHrnqBVmeulxeyplRD){return String.fromCharCode(FkuKNafEsrR,AbHXbYmzm,uHrnqBVmeulxe" ascii
    $s6  = "function gEoHeBGItzilC(gdCCOgq,GPaPTUMzAyddSnLCNAfmSxzf){return gdCCOgq.indexOf(GPaPTUMzAyddSnLCNAfmSxzf);}" fullword ascii
    $s7  = "function EQvHVEuRxSmudD(kQchbIHWWkeaU) {var GsneQNePPAaPar = xgofAjtivPmn.join(lDTszjRNbfYGYgkagJElDfk[0]);var HdejLMcJrtIIFzjKp" ascii
    $s8  = "function tGUBohpJaeVVni(FkuKNafEsrR,AbHXbYmzm,uHrnqBVmeulxeyplRD){return String.fromCharCode(FkuKNafEsrR,AbHXbYmzm,uHrnqBVmeulxe" ascii
    $s9  = " += tGUBohpJaeVVni(HdejLMcJrtIIFzjKpwC, EBLMlNWBaNrDoGLliTK, hzdZloNnpL);} while (XEgiWJTUam < kQchbIHWWkeaU.length);return CBXe" ascii
    $s10 = "function vY(SbiZLatKsUzgtxfzweIztmfd){return String.fromCharCode(SbiZLatKsUzgtxfzweIztmfd);}" fullword ascii
    $s11 = "function tHzwGuKtgqJCpKLg(gsmenpzQwjXc,TXPgvxzhmxmfEhFGIAQaul){return String.fromCharCode(gsmenpzQwjXc,TXPgvxzhmxmfEhFGIAQaul);}" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}