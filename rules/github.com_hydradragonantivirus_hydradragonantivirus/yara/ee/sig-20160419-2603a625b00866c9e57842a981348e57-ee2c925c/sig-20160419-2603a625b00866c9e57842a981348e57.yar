rule sig_20160419_2603a625b00866c9e57842a981348e57 {
  meta:
    description = "datamaliciousorder - file 20160419_2603a625b00866c9e57842a981348e57.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28858a1fb049937784cb098281fd57fed986e5afce54eab8129d58d016016c00"

  strings:
    $s1  = "return HKtRtAX[0] + HKtRtAX[2] + HKtRtAX[4] + \".F\" + HKtRtAX[7] + HKtRtAX[9] + HKtRtAX[12] + HKtRtAX[14];" fullword ascii
    $s2  = "var LA = true  , Etwc = vkB[7] + vkB[9] + vkB[11];" fullword ascii
    $s3  = "vuRi.open(JHujP,ycZXV,false);" fullword ascii
    $s4  = "var vkB = (\"2.XMLHTTP ONMwJJe rCxAv XML ream St MhMcYIKh AD equCsgu O Mkbo D\").split(\" \");" fullword ascii
    $s5  = "if(G>=b.length) {break;}" fullword ascii
    $s6  = "function hNTNmjHHh(QCXYw) {" fullword ascii
    $s7  = "function dJlcgiLT(QRJA) {" fullword ascii
    $s8  = "return VDAaay[mnqe[894-894]]=595-595;" fullword ascii
    $s9  = "return SlQLsVJ[0];" fullword ascii
    $s10 = "function Xvsw(qJpxb,HXqAW) {" fullword ascii
    $s11 = "function tVYetD(rQTX,xZYAdz) {" fullword ascii
    $s12 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s13 = "return ahRJuEZ(VC,sAaANR+smRtX[603-595]);" fullword ascii
    $s14 = "if (iZziD != 707-507){return false;} else {return true;}" fullword ascii
    $s15 = "function NxZjWQJ(gvwf) {" fullword ascii
    $s16 = "return deP[cXto[0]](sdSSE);" fullword ascii
    $s17 = "if (wdvzV > 153688-635){return true;} else {return false;}" fullword ascii
    $s18 = "return gvwf[NxtXJwV[0]+NxtXJwV[1]];" fullword ascii
    $s19 = "return Sje.size;" fullword ascii
    $s20 = "return new ActiveXObject(DkVo);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}