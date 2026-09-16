rule sig_20160323_0f36c7758a3bf7f64171e43a65f08999 {
  meta:
    description = "datamaliciousorder - file 20160323_0f36c7758a3bf7f64171e43a65f08999.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a32510344977daf842353f695499927c7ab5179fac52170323ffed55d24413c"

  strings:
    $s1  = "return WScript.CreateObject(TXnIZ);" fullword ascii
    $s2  = "var PS = true  , gMHk = iwp[7] + iwp[9] + iwp[11];" fullword ascii
    $s3  = "return GeVTerf[0] + GeVTerf[2] + GeVTerf[4] + \".F\" + GeVTerf[7] + GeVTerf[9] + GeVTerf[12] + GeVTerf[14];" fullword ascii
    $s4  = "NxhO.open(eAXIB,WEdgG,false);" fullword ascii
    $s5  = "var GeVTerf = GURrB(fbFITHihWY+\" \"+\"System Ny ZoQzO Obj YMNhQw ect NplgeuR gIBkY\", \" \");" fullword ascii
    $s6  = "var iwp = (\"2.XMLHTTP fQzofCx MoeNy XML ream St xQoyOSta AD TqitawK O tOWp D\").split(\" \");" fullword ascii
    $s7  = "if(C>=e.length) {break;}" fullword ascii
    $s8  = "function DSwj(IiIbm,gmooy) {" fullword ascii
    $s9  = "function UDeIbId(QsBH) {" fullword ascii
    $s10 = "function xFqvIbeG(FbQ) {" fullword ascii
    $s11 = "function KCzB(pIuFx) {" fullword ascii
    $s12 = "return FbQ.size;" fullword ascii
    $s13 = "function rFDSInS(hUBs,bicMp) {" fullword ascii
    $s14 = "if (JpmcX > 197689-475){return true;} else {return false;}" fullword ascii
    $s15 = "function JjFv(UUYMh,WEdgG,eAXIB) {" fullword ascii
    $s16 = "function ZxgA(RVnxT) {" fullword ascii
    $s17 = "return hUBs.ExpandEnvironmentStrings(bicMp);" fullword ascii
    $s18 = "function RRiAlgcKo(NBELPqmoFpB) {" fullword ascii
    $s19 = "function wVXl(eowkA) {" fullword ascii
    $s20 = "return eowkA.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}