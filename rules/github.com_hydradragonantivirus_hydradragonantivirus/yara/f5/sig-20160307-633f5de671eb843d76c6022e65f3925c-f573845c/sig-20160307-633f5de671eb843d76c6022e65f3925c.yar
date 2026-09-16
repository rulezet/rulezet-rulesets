rule sig_20160307_633f5de671eb843d76c6022e65f3925c {
  meta:
    description = "datamaliciousorder - file 20160307_633f5de671eb843d76c6022e65f3925c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf24d9fc955a02cc086bdc6580ea6d20f1213cc6d93fbd5f1603014a19ba91e0"

  strings:
    $s1  = "var TxH = (\"2.XMLHTTP DUafTPw tBrWQ XML ream St BEvNBCKK AD lQcreXK O Aams D\").split(\" \");" fullword ascii
    $s2  = "var bn = true  , WYFS = TxH[7] + TxH[9] + TxH[11];" fullword ascii
    $s3  = "return FHoViTA[0] + FHoViTA[2] + FHoViTA[4] + \".F\" + FHoViTA[7] + FHoViTA[9] + FHoViTA[12] + FHoViTA[14];" fullword ascii
    $s4  = "dUolM.open(zhlrm,XYnTD,false);" fullword ascii
    $s5  = "var FHoViTA = \"Sc ofEhgWN r uRhYEbLul ipting BOmuqYm xoz ile mrSOyNQSAKZgvS System Tt iJFqP Obj WMhvRA ect oAnOYIL\".split(\" " ascii
    $s6  = "function XkuT(nnpiN,jmUTC) {" fullword ascii
    $s7  = "return ueafe.status;" fullword ascii
    $s8  = "function HUwj(pTSLH) {" fullword ascii
    $s9  = "return Ujbmm.replace(new RegExp('!','g'), 'e');" fullword ascii
    $s10 = "function qvEZB(sbNneN) {" fullword ascii
    $s11 = "if (wxnjg == 896-696){return true;} else {return false;}" fullword ascii
    $s12 = "function VqgY(dUolM,XYnTD,zhlrm) {" fullword ascii
    $s13 = "function uEef(ZDsiE,celPA) {" fullword ascii
    $s14 = "function VfMpiEXjv(NRqcg,RLYsJ,SVGpY,mQsw) {" fullword ascii
    $s15 = "function dCYILMKlN(CsHFVYMEhmZ) {" fullword ascii
    $s16 = "if(z>=Q.length) {break;}" fullword ascii
    $s17 = "if (NvEWX > 194622-914){return true;} else {return false;}" fullword ascii
    $s18 = "function XEFQSOfI() {" fullword ascii
    $s19 = "return new ActiveXObject(sbNneN);" fullword ascii
    $s20 = "return ZZjQDYq" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}