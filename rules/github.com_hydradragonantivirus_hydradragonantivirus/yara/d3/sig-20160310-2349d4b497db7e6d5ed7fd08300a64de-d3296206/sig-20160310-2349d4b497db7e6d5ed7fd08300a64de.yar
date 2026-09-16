rule sig_20160310_2349d4b497db7e6d5ed7fd08300a64de {
  meta:
    description = "datamaliciousorder - file 20160310_2349d4b497db7e6d5ed7fd08300a64de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b7cdfd434e0c9e33168395f8156cd89fbdbe18560857461afab12ecde5d6a91"

  strings:
    $s1  = "return chxwbrB(uU,lftPm[690-684]+lftPm[213-206]+lftPm[309-301]);" fullword ascii
    $s2  = "var Mh = true  , aWaA = XjU[7] + XjU[9] + XjU[11];" fullword ascii
    $s3  = "return QcgGRBO[0] + QcgGRBO[2] + QcgGRBO[4] + \".F\" + QcgGRBO[7] + QcgGRBO[9] + QcgGRBO[12] + QcgGRBO[14];" fullword ascii
    $s4  = "var QcgGRBO = \"Sc skddELS r GgUTtwkGk ipting yCuTrIt XzD ile lnKElstLdBidnE System nG hUREK Obj dEybSZ ect MHjoRvz\".split(\" " ascii
    $s5  = "CKWCd.open(BeoCq,fDerj,false);" fullword ascii
    $s6  = "var XjU = (\"2.XMLHTTP mrQWGXO mvDFe XML ream St ObahVqRc AD RqoadLb O yZid D\").split(\" \");" fullword ascii
    $s7  = "return new ActiveXObject(gKFCnC);" fullword ascii
    $s8  = "return qgvc.responseBody;" fullword ascii
    $s9  = "function rzyB(OcUeG) {" fullword ascii
    $s10 = "function QCsAMhRg(EmkNG,zXMyNx) {" fullword ascii
    $s11 = "function OyuwYIsuY(lLCEI,SyBbJ,UpTHJ,IGTC) {" fullword ascii
    $s12 = "return ysItD;" fullword ascii
    $s13 = "function tYnZNhMw(wtD) {" fullword ascii
    $s14 = "function OtSxISFMN(dJRQPYgjfAX) {" fullword ascii
    $s15 = "if (H >= AhGko.length) {break;}" fullword ascii
    $s16 = "function YvWvCLc(qgvc) {" fullword ascii
    $s17 = "function chxwbrB(aLGE,KgNSO) {" fullword ascii
    $s18 = "function UdkV(NSmTL) {" fullword ascii
    $s19 = "function aEBr(JZwUa) {" fullword ascii
    $s20 = "return aLGE.ExpandEnvironmentStrings(KgNSO);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}