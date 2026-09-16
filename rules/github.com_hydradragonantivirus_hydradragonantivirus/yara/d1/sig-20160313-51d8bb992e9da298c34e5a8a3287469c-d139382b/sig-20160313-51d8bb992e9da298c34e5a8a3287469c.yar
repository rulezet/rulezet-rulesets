rule sig_20160313_51d8bb992e9da298c34e5a8a3287469c {
  meta:
    description = "datamaliciousorder - file 20160313_51d8bb992e9da298c34e5a8a3287469c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60c411b004b740ec5c4c14ab68e7606b713188b4ebfc14ec76fd19ec115b2624"

  strings:
    $s1  = "var AO = true  , lQMJ = PKG[7] + PKG[9] + PKG[11];" fullword ascii
    $s2  = "return kUyohOB[0] + kUyohOB[2] + kUyohOB[4] + \".F\" + kUyohOB[7] + kUyohOB[9] + kUyohOB[12] + kUyohOB[14];" fullword ascii
    $s3  = "var PKG = (\"2.XMLHTTP clMclco Gwasv XML ream St KJVSXTnJ AD hZXlkIe O NvDa D\").split(\" \");" fullword ascii
    $s4  = "ISXSk.open(bJUeB,BqPeC,false);" fullword ascii
    $s5  = "var kUyohOB = \"Sc CjBTHCQ r CIeeaRZDF ipting onRnOMc gDK ile cbAKfRzjiuIpGH System fA xcLzI Obj PUbRMD ect gXOxhXy\".split(\" " ascii
    $s6  = "return gZpoZYj(PV,NGarm[524-518]+NGarm[772-765]+NGarm[563-555]);" fullword ascii
    $s7  = "return FWm.size;" fullword ascii
    $s8  = "if (Y >= gjuRY.length) {break;}" fullword ascii
    $s9  = "function XJEy(UqKet,wrsVN) {" fullword ascii
    $s10 = "return EhgoQC.position=955-955;" fullword ascii
    $s11 = "function ddTp(hPssa,CPbVl) {" fullword ascii
    $s12 = "function joXI(gjuRY) {" fullword ascii
    $s13 = "function oRItV(ZrdIwV) {" fullword ascii
    $s14 = "function RekO(lftVc) {" fullword ascii
    $s15 = "function EacNDyDV(FWm) {" fullword ascii
    $s16 = "function cBFYhhp(ybUV) {" fullword ascii
    $s17 = "return ybUV.responseBody;" fullword ascii
    $s18 = "function eRaw(SuueF) {" fullword ascii
    $s19 = "if (hZjSW == 373-173){return true;} else {return false;}" fullword ascii
    $s20 = "return new ActiveXObject(ZrdIwV);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}