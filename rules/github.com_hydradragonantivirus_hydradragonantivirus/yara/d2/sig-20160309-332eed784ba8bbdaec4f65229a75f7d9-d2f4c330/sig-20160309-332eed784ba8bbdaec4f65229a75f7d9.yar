rule sig_20160309_332eed784ba8bbdaec4f65229a75f7d9 {
  meta:
    description = "datamaliciousorder - file 20160309_332eed784ba8bbdaec4f65229a75f7d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46d83eb2757a2929c4ea0fadc5e3814b36c1fadf282856f923308f085a675f75"

  strings:
    $s1  = "var kO = true  , dfUF = Zga[7] + Zga[9] + Zga[11];" fullword ascii
    $s2  = "return CDyCLEA[0] + CDyCLEA[2] + CDyCLEA[4] + \".F\" + CDyCLEA[7] + CDyCLEA[9] + CDyCLEA[12] + CDyCLEA[14];" fullword ascii
    $s3  = "var Zga = (\"2.XMLHTTP mlbQNJp XMKPt XML ream St eUpoWdcH AD VujsNMf O YoNf D\").split(\" \");" fullword ascii
    $s4  = "rwYiy.open(THrgZ,aniGO,false);" fullword ascii
    $s5  = "var CDyCLEA = \"Sc qVoxxCz r fjPQzQsWb ipting JnrVoTz Iey ile jvBHAKUpdIUzrg System vZ pNjPa Obj PVqghM ect HmQyBeo\".split(\" " ascii
    $s6  = "if (f >= WwVED.length) {break;}" fullword ascii
    $s7  = "function AuwVnLP(INPc) {" fullword ascii
    $s8  = "function QZTprXAvZ(dUaeC,EohyZ,JdqhN,LKEL) {" fullword ascii
    $s9  = "return INPc.responseBody;" fullword ascii
    $s10 = "return wwc.size;" fullword ascii
    $s11 = "function yrTVdnP(pNeW,zknQC) {" fullword ascii
    $s12 = "function jMroS(zxveFc) {" fullword ascii
    $s13 = "function dkRKDRvrE(vbXQGGjSpRw) {" fullword ascii
    $s14 = "function jHBA(hQDTg) {" fullword ascii
    $s15 = "function zCUyKrEQ(wwc) {" fullword ascii
    $s16 = "function LhiN(OGcBz,BEVYj) {" fullword ascii
    $s17 = "if (SrAeY == 1130-930){return true;} else {return false;}" fullword ascii
    $s18 = "if(h>=P.length) {break;}" fullword ascii
    $s19 = "function azNU(STIRP) {" fullword ascii
    $s20 = "function NqkPWmec() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}