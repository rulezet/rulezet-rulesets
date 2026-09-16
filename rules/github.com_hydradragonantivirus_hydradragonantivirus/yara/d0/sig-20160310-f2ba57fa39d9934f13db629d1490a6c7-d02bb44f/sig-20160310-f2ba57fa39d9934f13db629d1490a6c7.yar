rule sig_20160310_f2ba57fa39d9934f13db629d1490a6c7 {
  meta:
    description = "datamaliciousorder - file 20160310_f2ba57fa39d9934f13db629d1490a6c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "518b834903b957aa5aeb417daa514cf294b0ca50d070f0217d3c693d18c90c75"

  strings:
    $s1  = "var Rx = true  , qVdV = PZQ[7] + PZQ[9] + PZQ[11];" fullword ascii
    $s2  = "return jaNldJs[0] + jaNldJs[2] + jaNldJs[4] + \".F\" + jaNldJs[7] + jaNldJs[9] + jaNldJs[12] + jaNldJs[14];" fullword ascii
    $s3  = "kISog.open(QFhxF,pfIUO,false);" fullword ascii
    $s4  = "var PZQ = (\"2.XMLHTTP mDByNpO qLwep XML ream St JKmOimsk AD SuHEqpW O AZqj D\").split(\" \");" fullword ascii
    $s5  = "var jaNldJs = \"Sc tMlEfYw r fQpmYliKm ipting aQafAxY jvn ile tWtHYuVAfPMVRg System vB wSRSl Obj rCgIdW ect azVHpZY\".split(\" " ascii
    $s6  = "function cswY(inexK) {" fullword ascii
    $s7  = "dD = 1;vgBUO(MOj);Heii(MOj,/*Wgs262ArLO*/fohI/*sp6E25dpMi*/+JBaXNEr+vfc[7]+vfc[9]+vfc[11]); try  {" fullword ascii
    $s8  = "if (inexK > 178226-568){return true;} else {return false;}" fullword ascii
    $s9  = "return new ActiveXObject(AwIbmC);" fullword ascii
    $s10 = "function MwJI(kQSLx) {" fullword ascii
    $s11 = "function zLQR(DesLN) {" fullword ascii
    $s12 = "return niI.size;" fullword ascii
    $s13 = "function PSNMlCNQ() {" fullword ascii
    $s14 = "return dahFU;" fullword ascii
    $s15 = "function WHAF(RuhFz) {" fullword ascii
    $s16 = "function YoKMVFft(niI) {" fullword ascii
    $s17 = "return vfPhbJR(ph,Ngnsq[753-747]+Ngnsq[701-694]+Ngnsq[846-838]);" fullword ascii
    $s18 = "function FmOZ(aWRQk) {" fullword ascii
    $s19 = "function EPwwZ(AwIbmC) {" fullword ascii
    $s20 = "function hLdxJpVYv(EcNRcgvQGeZ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}