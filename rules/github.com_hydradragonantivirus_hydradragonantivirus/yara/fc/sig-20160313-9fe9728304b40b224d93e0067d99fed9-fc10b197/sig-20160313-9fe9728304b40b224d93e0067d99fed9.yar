rule sig_20160313_9fe9728304b40b224d93e0067d99fed9 {
  meta:
    description = "datamaliciousorder - file 20160313_9fe9728304b40b224d93e0067d99fed9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49ef77919a0be7ca3ff676f99269980512dd2f6b3ccf8324b5343dd6243ad175"

  strings:
    $s1  = "function iRCu(XCINb) {" fullword ascii
    $s2  = "var Yl = true  , tCDz = NAM[7] + NAM[9] + NAM[11];" fullword ascii
    $s3  = "return voFaMiW[0] + voFaMiW[2] + voFaMiW[4] + \".F\" + voFaMiW[7] + voFaMiW[9] + voFaMiW[12] + voFaMiW[14];" fullword ascii
    $s4  = "var voFaMiW = \"Sc taYcylC r HowdEdTei ipting IRXXMqp dAB ile kmDfmotgVlnXbs System rU YskOS Obj WaACqA ect sZEOEIv\".split(\" " ascii
    $s5  = "uYjSb.open(odJDx,mZjQo,false);" fullword ascii
    $s6  = "var NAM = (\"2.XMLHTTP JYnidop vDYGc XML ream St oTjGGavK AD XzVnHVp O KaiR D\").split(\" \");" fullword ascii
    $s7  = "return new ActiveXObject(sPFZqV);" fullword ascii
    $s8  = "function swAJ(iwVTL) {" fullword ascii
    $s9  = "if (z >= UyoIm.length) {break;}" fullword ascii
    $s10 = "if (iwVTL > 188812-776){return true;} else {return false;}" fullword ascii
    $s11 = "return zYplVxw" fullword ascii
    $s12 = "function NKCWbQmYh(MqNRwBanITb) {" fullword ascii
    $s13 = "function eNeUgfQ(VXlU,lntEo) {" fullword ascii
    $s14 = "function YkWOZMIPs() {" fullword ascii
    $s15 = "return inFuN;" fullword ascii
    $s16 = "function MTNa(wshvL,nnPMY) {" fullword ascii
    $s17 = "function zORk(ZcZdI) {" fullword ascii
    $s18 = "return OsZ.size;" fullword ascii
    $s19 = "function dVzPsbY(uFCw) {" fullword ascii
    $s20 = "return uFCw.responseBody;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}