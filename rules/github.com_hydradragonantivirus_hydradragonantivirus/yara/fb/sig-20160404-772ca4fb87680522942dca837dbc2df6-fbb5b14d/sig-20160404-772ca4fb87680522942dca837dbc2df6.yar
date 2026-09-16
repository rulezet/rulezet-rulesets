rule sig_20160404_772ca4fb87680522942dca837dbc2df6 {
  meta:
    description = "datamaliciousorder - file 20160404_772ca4fb87680522942dca837dbc2df6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "499848ab04891aa9d378ec312587996cbc074bbaaf27b5808880ad45755ab2d7"

  strings:
    $s1  = "var di = true  , FKdL = vAN[7] + vAN[9] + vAN[11];" fullword ascii
    $s2  = "return ezIJtyU[0] + ezIJtyU[2] + ezIJtyU[4] + \".F\" + ezIJtyU[7] + ezIJtyU[9] + ezIJtyU[12] + ezIJtyU[14];" fullword ascii
    $s3  = "var ezIJtyU = gbCzq(rUrNemuGDg+\" \"+\"System wc AbznE Obj eAKumo ect MkgnvcQ ZZaLW\", \" \");" fullword ascii
    $s4  = "BMIN.open(ZRwaj,QTgWa,false);" fullword ascii
    $s5  = "var vAN = (\"2.XMLHTTP ZPJaZRs klzMc XML ream St dFwibSVe AD lvOeVLz O QMuZ D\").split(\" \");" fullword ascii
    $s6  = "return dzJy;" fullword ascii
    $s7  = "if (K >= UeGMp.length) {break;}" fullword ascii
    $s8  = "function pAvUQJs(FZtG,bGeoF) {" fullword ascii
    $s9  = "function OaAbV(ZIijfj) {" fullword ascii
    $s10 = "function WudAIx(DIbwNIn) {" fullword ascii
    $s11 = "function cYvhgSUcl(QQOPc) {" fullword ascii
    $s12 = "return zPs.size;" fullword ascii
    $s13 = "return pAvUQJs(lE,BHlQd[931-925]+BHlQd[160-153]+BHlQd[650-642]);" fullword ascii
    $s14 = "function Ladt(UeGMp) {" fullword ascii
    $s15 = "return CyMhS.status;" fullword ascii
    $s16 = "function OdaOYn(lnCz,LDOqwL) {" fullword ascii
    $s17 = "function nVbSWBt(lbqI) {" fullword ascii
    $s18 = "return \"hckWmbEHkWqDNn\";" fullword ascii
    $s19 = "return aoq.split(AVKns);" fullword ascii
    $s20 = "function zXdPd(hKCoqRbY,HhKw) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}