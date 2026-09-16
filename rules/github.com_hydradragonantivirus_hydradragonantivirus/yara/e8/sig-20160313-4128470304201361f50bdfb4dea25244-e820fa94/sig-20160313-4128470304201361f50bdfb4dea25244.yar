rule sig_20160313_4128470304201361f50bdfb4dea25244 {
  meta:
    description = "datamaliciousorder - file 20160313_4128470304201361f50bdfb4dea25244.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d40f08bbddb85ad1a9eecd0256fdd1cdbb3ab73de443aaf962d2f5b681f22fa8"

  strings:
    $s1  = "return EyKplLw[0] + EyKplLw[2] + EyKplLw[4] + \".F\" + EyKplLw[7] + EyKplLw[9] + EyKplLw[12] + EyKplLw[14];" fullword ascii
    $s2  = "var rw = true  , UYHu = iRM[7] + iRM[9] + iRM[11];" fullword ascii
    $s3  = "var iRM = (\"2.XMLHTTP lsiJiLd kTBzo XML ream St fYmKlqDV AD NLDTKlq O MXKl D\").split(\" \");" fullword ascii
    $s4  = "svSbu.open(khfHK,isNQL,false);" fullword ascii
    $s5  = "if(Z>=d.length) {break;}" fullword ascii
    $s6  = "return vLbeFLC(Ut,uWCGo[286-280]+uWCGo[300-293]+uWCGo[611-603]);" fullword ascii
    $s7  = "function seIo(NLceJ) {" fullword ascii
    $s8  = "function UqUJ(lJYTr) {" fullword ascii
    $s9  = "function FHjSy(XFwOuR) {" fullword ascii
    $s10 = "function puJRPGuI(ZGq) {" fullword ascii
    $s11 = "return vKQc.ExpandEnvironmentStrings(CliGh);" fullword ascii
    $s12 = "function GciF(vLLWu,XBJYd) {" fullword ascii
    $s13 = "function rkcp(ileZF) {" fullword ascii
    $s14 = "function yGsp(djJUH) {" fullword ascii
    $s15 = "return NLceJ.status;" fullword ascii
    $s16 = "return XFwOuR.position=268-268;" fullword ascii
    $s17 = "function LVIBCFWs() {" fullword ascii
    $s18 = "function JgGp(nwAOe,kSlLR) {" fullword ascii
    $s19 = "return ZGq.size;" fullword ascii
    $s20 = "function CPQeM(ZtMObv) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}