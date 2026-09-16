rule sig_20160309_f6869e7c240a9d17a2b7429f7213a2ea {
  meta:
    description = "datamaliciousorder - file 20160309_f6869e7c240a9d17a2b7429f7213a2ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "779e7ac0ba985d01c7e848aedd1495312affdba4dcc2f16e5bc9b5adaf24e6cc"

  strings:
    $s1  = "var Jc = true  , KyCN = QQZ[7] + QQZ[9] + QQZ[11];" fullword ascii
    $s2  = "return sicSxMP[0] + sicSxMP[2] + sicSxMP[4] + \".F\" + sicSxMP[7] + sicSxMP[9] + sicSxMP[12] + sicSxMP[14];" fullword ascii
    $s3  = "var sicSxMP = \"Sc JWUNYVT r RkxJEPIvS ipting KSzguZW GYo ile pdLXWveiQdqoHr System ff eYYTo Obj MZfmtK ect hrmBPxZ\".split(\" " ascii
    $s4  = "var QQZ = (\"2.XMLHTTP cHahBie OOMeD XML ream St vZxLvJYe AD yGtCWiR O AzTa D\").split(\" \");" fullword ascii
    $s5  = "XNKHk.open(JieRL,VGPpn,false);" fullword ascii
    $s6  = "if(p>=n.length) {break;}" fullword ascii
    $s7  = "return LGW.size;" fullword ascii
    $s8  = "function qlTY(snFsv,Uylvl) {" fullword ascii
    $s9  = "Tym = p; break; " fullword ascii
    $s10 = "function okpm(WcqBK) {" fullword ascii
    $s11 = "function ypvL(XYMIT) {" fullword ascii
    $s12 = "function ywGHJYoi(LGW) {" fullword ascii
    $s13 = "return new ActiveXObject(WAMiLH);" fullword ascii
    $s14 = "function VsWZ(AhkaE) {" fullword ascii
    $s15 = "function RVvC(XNKHk,VGPpn,JieRL) {" fullword ascii
    $s16 = "function UHWT(KBUtv,JVgct) {" fullword ascii
    $s17 = "function KbeAATD(jQtm,wtTvf) {" fullword ascii
    $s18 = "return jQtm.ExpandEnvironmentStrings(wtTvf);" fullword ascii
    $s19 = "return YntUM.status;" fullword ascii
    $s20 = "function ReCc(JFUMY) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}