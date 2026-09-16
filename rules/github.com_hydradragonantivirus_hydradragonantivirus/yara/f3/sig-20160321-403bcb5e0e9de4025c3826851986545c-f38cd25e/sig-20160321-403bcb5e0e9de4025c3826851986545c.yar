rule sig_20160321_403bcb5e0e9de4025c3826851986545c {
  meta:
    description = "datamaliciousorder - file 20160321_403bcb5e0e9de4025c3826851986545c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ddd7a6dd55030313bbfec4eadd439787a8439ad9113fcdf1f69501c98589333"

  strings:
    $s1  = "return WScript.CreateObject(BxGGo);" fullword ascii
    $s2  = "return VdSzEXy[0] + VdSzEXy[2] + VdSzEXy[4] + \".F\" + VdSzEXy[7] + VdSzEXy[9] + VdSzEXy[12] + VdSzEXy[14];" fullword ascii
    $s3  = "var HE = true  , hGeh = gJy[7] + gJy[9] + gJy[11];" fullword ascii
    $s4  = "var gJy = (\"2.XMLHTTP KEOUvqB EtwNs XML ream St cvdSwIya AD GdplDUl O BlfU D\").split(\" \");" fullword ascii
    $s5  = "var VdSzEXy = mlAnM(VOBJgqWLnk+\" \"+\"System UL TtVLZ Obj UeiiMg ect uAqimtT WMsSd\", \" \");" fullword ascii
    $s6  = "VEKgm.open(HBJBv,jYcYD,false);" fullword ascii
    $s7  = "if(J>=x.length) {break;}" fullword ascii
    $s8  = "function ECDrDOuqr(aXxBm) {" fullword ascii
    $s9  = "function VUkJ(WfcBO,HLoet) {" fullword ascii
    $s10 = "function sJVPsSQj(KSfr) {" fullword ascii
    $s11 = "function EvCY(looLO) {" fullword ascii
    $s12 = "function FsxM(VEKgm,jYcYD,HBJBv) {" fullword ascii
    $s13 = "return WOyvjE.position=441-441;" fullword ascii
    $s14 = "function AslMFjXmQ(OqpDFojYQpK) {" fullword ascii
    $s15 = "function mlAnM(MJD,VlHog) {" fullword ascii
    $s16 = "function ZdNOmqau(Fko) {" fullword ascii
    $s17 = "if (xkhsX == 714-514){return true;} else {return false;}" fullword ascii
    $s18 = "function oyDe(WjsTx) {" fullword ascii
    $s19 = "if (W >= WjsTx.length) {break;}" fullword ascii
    $s20 = "function VBDi(BxGGo) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}