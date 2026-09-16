rule sig_20160411_c88c3a7f9bd9963352e8005de8a8d84a {
  meta:
    description = "datamaliciousorder - file 20160411_c88c3a7f9bd9963352e8005de8a8d84a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e4d0be441faac07752cde1969562150ba0dc1994366a7b715c7b23f700ce4a8"

  strings:
    $s1  = "function GlOG(xIojl) {" fullword ascii
    $s2  = "var Wj = true  , MGDI = RNk[7] + RNk[9] + RNk[11];" fullword ascii
    $s3  = "return vAvVnXh[0] + vAvVnXh[2] + vAvVnXh[4] + \".F\" + vAvVnXh[7] + vAvVnXh[9] + vAvVnXh[12] + vAvVnXh[14];" fullword ascii
    $s4  = "qFrI.open(AahDd,fUaju,false);" fullword ascii
    $s5  = "var RNk = (\"2.XMLHTTP aNIcpVU kLZJz XML ream St TxCYlxQf AD VKycqVv O qRrG D\").split(\" \");" fullword ascii
    $s6  = "function tOGC(nQXQf) {" fullword ascii
    $s7  = "function hgPeoS(okzvKNe) {" fullword ascii
    $s8  = "function TQgMWZuzQ(yvpaG) {" fullword ascii
    $s9  = "function luqBB(CoBlYq) {" fullword ascii
    $s10 = "function FZKAhOPRj(KkkowtdHGbg) {" fullword ascii
    $s11 = "if (xIojl > 193286-487){return true;} else {return false;}" fullword ascii
    $s12 = "function xuPJ(cRphg,EUZLJ) {" fullword ascii
    $s13 = "function Nahrz(UzC,MGzjh) {" fullword ascii
    $s14 = "return UzC[cFJm[0]](MGzjh);" fullword ascii
    $s15 = "function wIIW(MOZFQ,fUaju,AahDd) {" fullword ascii
    $s16 = "function tYSBG(lXjMeghe,EpkZ) {" fullword ascii
    $s17 = "function HKrqw(wxALtS) {" fullword ascii
    $s18 = "function KHKk(mpMWX,apXhx) {" fullword ascii
    $s19 = "function vkPSva(JYEJ,apUtIz) {" fullword ascii
    $s20 = "return sjEsx;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}