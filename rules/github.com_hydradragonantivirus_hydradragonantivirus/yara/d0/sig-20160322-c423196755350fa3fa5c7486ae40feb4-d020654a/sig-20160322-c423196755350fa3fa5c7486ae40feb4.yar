rule sig_20160322_c423196755350fa3fa5c7486ae40feb4 {
  meta:
    description = "datamaliciousorder - file 20160322_c423196755350fa3fa5c7486ae40feb4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "913311e5d65f4ad93266143f251b09d174717f1e61367716b37c132e1d9a1d50"

  strings:
    $s1  = "return WScript.CreateObject(buwit);" fullword ascii
    $s2  = "return wSNhnGo[0] + wSNhnGo[2] + wSNhnGo[4] + \".F\" + wSNhnGo[7] + wSNhnGo[9] + wSNhnGo[12] + wSNhnGo[14];" fullword ascii
    $s3  = "var mM = true  , LrMx = GLi[7] + GLi[9] + GLi[11];" fullword ascii
    $s4  = "var wSNhnGo = quaTZ(TEldAITphZ+\" \"+\"System FW rwmTt Obj ruXdLn ect lYgbmtp VokNp\", \" \");" fullword ascii
    $s5  = "var GLi = (\"2.XMLHTTP bSbTDgd rfOeT XML ream St NUXxzBqP AD yrKsYFb O MsSk D\").split(\" \");" fullword ascii
    $s6  = "iXPb.open(TAZCI,PWDtH,false);" fullword ascii
    $s7  = "if(n>=x.length) {break;}" fullword ascii
    $s8  = "function yNxttgOf(KiI) {" fullword ascii
    $s9  = "function ARhY(UBbja) {" fullword ascii
    $s10 = "return xtXX[UidHir[0]];" fullword ascii
    $s11 = "return lYl.split(JipjZ);" fullword ascii
    $s12 = "return SnDeOIO(rs,XsWrN[366-360]+XsWrN[962-955]+XsWrN[664-656]);" fullword ascii
    $s13 = "return MpVGJS.position=741-741;" fullword ascii
    $s14 = "function NdiJYGxXR(CWHoI) {" fullword ascii
    $s15 = "function jglP(tJefi,BNORX) {" fullword ascii
    $s16 = "function shPZ(PhSWP) {" fullword ascii
    $s17 = "return BbLE.ExpandEnvironmentStrings(aDmcr);" fullword ascii
    $s18 = "return KiI.size;" fullword ascii
    $s19 = "if (K >= MAirf.length) {break;}" fullword ascii
    $s20 = "function Upqz(buwit) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}