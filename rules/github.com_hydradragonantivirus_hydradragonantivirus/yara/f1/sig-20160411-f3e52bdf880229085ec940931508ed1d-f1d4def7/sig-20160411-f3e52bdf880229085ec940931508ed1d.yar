rule sig_20160411_f3e52bdf880229085ec940931508ed1d {
  meta:
    description = "datamaliciousorder - file 20160411_f3e52bdf880229085ec940931508ed1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84a75af4bc2c58d833ba54dd5349cc14a4b25a0fd7947993d62fbb5b06cb3db9"

  strings:
    $s1  = "var FqG = YJub(MIle + \"B.\" + ALv[5]+(86632, ALv[4]));" fullword ascii
    $s2  = "var mD = true  , MIle = ALv[7] + ALv[9] + ALv[11];" fullword ascii
    $s3  = "return uXenCnt[0] + uXenCnt[2] + uXenCnt[4] + \".F\" + uXenCnt[7] + uXenCnt[9] + uXenCnt[12] + uXenCnt[14];" fullword ascii
    $s4  = "var ALv = (\"2.XMLHTTP aPalFoS DBszA XML ream St DyUctrkW AD zbGckIE O ntLF D\").split(\" \");" fullword ascii
    $s5  = "OGgp.open(bIOhb,EOZny,false);" fullword ascii
    $s6  = "if(o>=q.length) {break;}" fullword ascii
    $s7  = "function MBgq(OkoYH) {" fullword ascii
    $s8  = "iRe = o; break; " fullword ascii
    $s9  = "function AAKe(DanRI,EOZny,bIOhb) {" fullword ascii
    $s10 = "return zDjwZ.status;" fullword ascii
    $s11 = "return uMGXp;" fullword ascii
    $s12 = "function sbacwRjx(CGf) {" fullword ascii
    $s13 = "function HFRl(RlsQd) {" fullword ascii
    $s14 = "function rWsef(ifW,PVWZe) {" fullword ascii
    $s15 = "function osVwnd(bVye,icWsrK) {" fullword ascii
    $s16 = "return ifW[Iacb[0]](PVWZe);" fullword ascii
    $s17 = "function uDsNC(LyoOMh) {" fullword ascii
    $s18 = "return kLqwIWJ;" fullword ascii
    $s19 = "function mEBRR(CkxXKv) {" fullword ascii
    $s20 = "return vBMWPIU[0];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}