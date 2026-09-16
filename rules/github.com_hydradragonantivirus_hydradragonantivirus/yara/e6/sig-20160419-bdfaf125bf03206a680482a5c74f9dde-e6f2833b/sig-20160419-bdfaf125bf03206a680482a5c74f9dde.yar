rule sig_20160419_bdfaf125bf03206a680482a5c74f9dde {
  meta:
    description = "datamaliciousorder - file 20160419_bdfaf125bf03206a680482a5c74f9dde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0d710dcec6fc7d8ace58425e0d221aca79614961256c09782c18786866db72f"

  strings:
    $s1  = "var IY = true  , igFC = MBj[7] + MBj[9] + MBj[11];" fullword ascii
    $s2  = "return OMOzYnN[0] + OMOzYnN[2] + OMOzYnN[4] + \".F\" + OMOzYnN[7] + OMOzYnN[9] + OMOzYnN[12] + OMOzYnN[14];" fullword ascii
    $s3  = "EQyc.open(HhAOK,bZVAQ,false);" fullword ascii
    $s4  = "var MBj = (\"2.XMLHTTP zMOfOop QtnfX XML ream St VaVIsVuf AD ruIXerY O DMlD D\").split(\" \");" fullword ascii
    $s5  = "if (NVaSV > 181895-618){return true;} else {return false;}" fullword ascii
    $s6  = "return QwA[rJWq[0]](ghQlF);" fullword ascii
    $s7  = "function fpjXC(dhDeFQ) {" fullword ascii
    $s8  = "function Qxcd(QWOKg,bZVAQ,HhAOK) {" fullword ascii
    $s9  = "function nrPE(NVaSV) {" fullword ascii
    $s10 = "YOB = I; break; " fullword ascii
    $s11 = "return \"gcGXXbSVroEzbn\";" fullword ascii
    $s12 = "return SnVwP;" fullword ascii
    $s13 = "function fbHJ(iOSjn) {" fullword ascii
    $s14 = "return BOgXcTP(Fi,rWIJSJ+rSfSS[744-736]);" fullword ascii
    $s15 = "return dhDeFQ[kFzw[538-538]]=577-577;" fullword ascii
    $s16 = "function mIpDYPSn(UrQ) {" fullword ascii
    $s17 = "function QTvqO(jgwWyChx,Oaxf) {" fullword ascii
    $s18 = "if(I>=s.length) {break;}" fullword ascii
    $s19 = "function Jckg(EJMWM) {" fullword ascii
    $s20 = "function WsdME(OkdyyM) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}