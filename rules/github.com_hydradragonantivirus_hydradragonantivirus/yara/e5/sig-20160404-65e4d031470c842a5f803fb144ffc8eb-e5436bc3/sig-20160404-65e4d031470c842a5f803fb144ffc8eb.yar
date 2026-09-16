rule sig_20160404_65e4d031470c842a5f803fb144ffc8eb {
  meta:
    description = "datamaliciousorder - file 20160404_65e4d031470c842a5f803fb144ffc8eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a00b0c6271fef3dfa643d32afceed3a99e3613937eec166d4e2db6994d0c492"

  strings:
    $s1  = "return qDKpovv[0] + qDKpovv[2] + qDKpovv[4] + \".F\" + qDKpovv[7] + qDKpovv[9] + qDKpovv[12] + qDKpovv[14];" fullword ascii
    $s2  = "var yC = true  , YAaa = Lvj[7] + Lvj[9] + Lvj[11];" fullword ascii
    $s3  = "hCCy.open(SFoHJ,OWrQo,false);" fullword ascii
    $s4  = "var qDKpovv = HuWOe(QhNTzxKAhz+\" \"+\"System wT kFBlU Obj xHpVnr ect WMQbTJi Qzfqe\", \" \");" fullword ascii
    $s5  = "var Lvj = (\"2.XMLHTTP sizVXhE NOCYl XML ream St rtFfTJxK AD obIGkkb O nBbv D\").split(\" \");" fullword ascii
    $s6  = "if(f>=w.length) {break;}" fullword ascii
    $s7  = "function tyAa(vWgFB) {" fullword ascii
    $s8  = "function DRcB(AtPZc) {" fullword ascii
    $s9  = "function OknV(EFkWk) {" fullword ascii
    $s10 = "if (X >= NrwNP.length) {break;}" fullword ascii
    $s11 = "if (ayssM > 156490-962){return true;} else {return false;}" fullword ascii
    $s12 = "return ihia[frotKj[0]];" fullword ascii
    $s13 = "return pGo.size;" fullword ascii
    $s14 = "EcfDM[goLA[225-225]](pzOKZj);" fullword ascii
    $s15 = "function Ngcy(kQIAa) {" fullword ascii
    $s16 = "function Okkw(AikOy,ZDdxv) {" fullword ascii
    $s17 = "function XIYpC(TPvurn) {" fullword ascii
    $s18 = "return FcXYQyC;" fullword ascii
    $s19 = "function CKFtAEeoL(QoiDJbxFXKi) {" fullword ascii
    $s20 = "return new ActiveXObject(eiLL);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}