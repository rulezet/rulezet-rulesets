rule sig_20160309_33128d2d8ffc13170690795aaa3e137b {
  meta:
    description = "datamaliciousorder - file 20160309_33128d2d8ffc13170690795aaa3e137b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a518f2680063368998cff3bc828109a1fb512ced54fb9e02e3ac814147954856"

  strings:
    $s1  = "var Jx = true  , GOrW = zqd[7] + zqd[9] + zqd[11];" fullword ascii
    $s2  = "return knJNMke[0] + knJNMke[2] + knJNMke[4] + \".F\" + knJNMke[7] + knJNMke[9] + knJNMke[12] + knJNMke[14];" fullword ascii
    $s3  = "var knJNMke = \"Sc EFzmszH r alVGtpqjl ipting RGqRHOd GEP ile wxULGcVvzLyRAM System ji QlNOU Obj kcCyeF ect jblufIB\".split(\" " ascii
    $s4  = "XvJer.open(qWgKe,nNcwY,false);" fullword ascii
    $s5  = "var zqd = (\"2.XMLHTTP AJizrio KnlLy XML ream St zjFQzVIc AD jGuKIpE O KBNB D\").split(\" \");" fullword ascii
    $s6  = "function VAeWjRCc(lwN) {" fullword ascii
    $s7  = "function DTdF(yuQeL,uAQtE) {" fullword ascii
    $s8  = "function JgUB(ykRKq,NKrMY) {" fullword ascii
    $s9  = "var nd = GheE(SM).split(\" \");" fullword ascii
    $s10 = "if (bDqvt == 884-684){return true;} else {return false;}" fullword ascii
    $s11 = "UoO = x; break; " fullword ascii
    $s12 = "function kqPRYrRh(PSRxu,fgRRxy) {" fullword ascii
    $s13 = "function gLbn(gDCGL) {" fullword ascii
    $s14 = "if (c >= dmXCW.length) {break;}" fullword ascii
    $s15 = "function wPefdJktE(urbav,WuGyE,hUBZP,OoMZ) {" fullword ascii
    $s16 = "function BHdc(YoByx) {" fullword ascii
    $s17 = "function qTEZ(JkxOP) {" fullword ascii
    $s18 = "return AAane;" fullword ascii
    $s19 = "function dCNm(XvJer,nNcwY,qWgKe) {" fullword ascii
    $s20 = "return KIUf.ExpandEnvironmentStrings(qUEIn);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}