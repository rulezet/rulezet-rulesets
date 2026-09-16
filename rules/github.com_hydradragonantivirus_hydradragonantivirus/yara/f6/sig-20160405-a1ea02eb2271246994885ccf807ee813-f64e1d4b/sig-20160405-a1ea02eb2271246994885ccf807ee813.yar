rule sig_20160405_a1ea02eb2271246994885ccf807ee813 {
  meta:
    description = "datamaliciousorder - file 20160405_a1ea02eb2271246994885ccf807ee813.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb3e29dc72561218f47b0295a8c7a1152374b637f55614a14cc6335f8f2318b3"

  strings:
    $s1  = "return CXNPmbx[0] + CXNPmbx[2] + CXNPmbx[4] + \".F\" + CXNPmbx[7] + CXNPmbx[9] + CXNPmbx[12] + CXNPmbx[14];" fullword ascii
    $s2  = "var Np = true  , ShPs = EGa[7] + EGa[9] + EGa[11];" fullword ascii
    $s3  = "Lbzr.open(YdoMO,QDwIR,false);" fullword ascii
    $s4  = "var EGa = (\"2.XMLHTTP qjCXIah Zekkf XML ream St sRAfanix AD kPZqIPZ O hwPN D\").split(\" \");" fullword ascii
    $s5  = "if (B >= Ltxcu.length) {break;}" fullword ascii
    $s6  = "var bgXUZZp = \"lodYuk*QPZ*pt.S\"+\"hell*zhmEUMW*Scri*\";" fullword ascii
    $s7  = "function bPkm(BHDUg,JrLSZ) {" fullword ascii
    $s8  = "function ADxZnC(qSdNWhm) {" fullword ascii
    $s9  = "return vdiVoFf(Mz,XwsBz[902-896]+XwsBz[272-265]+XwsBz[335-327]);" fullword ascii
    $s10 = "function FZGl(Ltxcu) {" fullword ascii
    $s11 = "function vdiVoFf(xKZO,vUNzh) {" fullword ascii
    $s12 = "function TLuwON(ODmP,IbXVWz) {" fullword ascii
    $s13 = "function svuWuJyn(xOb) {" fullword ascii
    $s14 = "return new ActiveXObject(FlPS);" fullword ascii
    $s15 = "return \"KHHvmjzNSGuPuN\";" fullword ascii
    $s16 = "function WZLVAIpjF(phHXt) {" fullword ascii
    $s17 = "function PRSu(jJbDu) {" fullword ascii
    $s18 = "return hurD[MinMFz[0]];" fullword ascii
    $s19 = "return NuRefTA;" fullword ascii
    $s20 = "function sWPl(SdrqN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}