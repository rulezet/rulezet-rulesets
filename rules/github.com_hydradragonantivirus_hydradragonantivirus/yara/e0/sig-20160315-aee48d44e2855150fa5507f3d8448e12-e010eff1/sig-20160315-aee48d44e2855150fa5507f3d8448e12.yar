rule sig_20160315_aee48d44e2855150fa5507f3d8448e12 {
  meta:
    description = "datamaliciousorder - file 20160315_aee48d44e2855150fa5507f3d8448e12.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f82de9366f455526e4f1990c97d1be748344406acea6152b1f192ba51c9509f"

  strings:
    $s1  = "var WB = true  , sbhw = blb[7] + blb[9] + blb[11];" fullword ascii
    $s2  = "return rFXqVhm[0] + rFXqVhm[2] + rFXqVhm[4] + \".F\" + rFXqVhm[7] + rFXqVhm[9] + rFXqVhm[12] + rFXqVhm[14];" fullword ascii
    $s3  = "var rFXqVhm = xyxJa(\"Sc NrgbziI r WrepZxmDt ipting FCwGjyU JVB ile XISVGkxLvTrFCU System rX AADFd Obj effxCY ect IWceGoB UIqff" ascii
    $s4  = "var blb = (\"2.XMLHTTP ibMwgwR FHmLP XML ream St IoCPuRdf AD svstMZc O onoY D\").split(\" \");" fullword ascii
    $s5  = "YjODl.open(oyoQH,KhclI,false);" fullword ascii
    $s6  = "var rFXqVhm = xyxJa(\"Sc NrgbziI r WrepZxmDt ipting FCwGjyU JVB ile XISVGkxLvTrFCU System rX AADFd Obj effxCY ect IWceGoB UIqff" ascii
    $s7  = "return bOOcQe.position=335-335;" fullword ascii
    $s8  = "function KhCxj(bOOcQe) {" fullword ascii
    $s9  = "function sPEI(vZVms) {" fullword ascii
    $s10 = "function KaHZW(AfjygK) {" fullword ascii
    $s11 = "function xhxdpTl(Ttbv,vYdEW) {" fullword ascii
    $s12 = "return xhxdpTl(XR,gCPRV[652-646]+gCPRV[553-546]+gCPRV[438-430]);" fullword ascii
    $s13 = "function XYuQsjq(jdpj) {" fullword ascii
    $s14 = "function DyvR(RFEli) {" fullword ascii
    $s15 = "function eyCoezYsh(XNZOa) {" fullword ascii
    $s16 = "if (vZVms == 948-748){return true;} else {return false;}" fullword ascii
    $s17 = "function GmuTdekA(AUQ) {" fullword ascii
    $s18 = "return XEysC.status;" fullword ascii
    $s19 = "function uAMj(CxJcM,OxPdX) {" fullword ascii
    $s20 = "cj = 1;KhCxj(JLF);PiLy(JLF,/*nAZe89V6k8*/Tjyl/*WkFa47Seo7*/+kdngtZT+MNr[511-504]+MNr[960-951]+MNr[175-164]); try  {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}