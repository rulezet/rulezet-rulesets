rule sig_20160321_fa87fb72ebc88e0106e2d6a1270b4d21 {
  meta:
    description = "datamaliciousorder - file 20160321_fa87fb72ebc88e0106e2d6a1270b4d21.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb2cd57d8de34307a6508c9cdfbc9d3738e1d394ab381a16087d731b2b3b9f14"

  strings:
    $s1  = "return WScript.CreateObject(PwjGt);" fullword ascii
    $s2  = "return YXvcHfv[0] + YXvcHfv[2] + YXvcHfv[4] + \".F\" + YXvcHfv[7] + YXvcHfv[9] + YXvcHfv[12] + YXvcHfv[14];" fullword ascii
    $s3  = "var Ij = true  , dRxa = Uuh[7] + Uuh[9] + Uuh[11];" fullword ascii
    $s4  = "var YXvcHfv = glhzl(HZPAfZsLni+\" \"+\"System Zk TjSTb Obj zWSFIz ect KCuqFQS FOosP\", \" \");" fullword ascii
    $s5  = "var Uuh = (\"2.XMLHTTP QJLjgVA VopRc XML ream St LObRApTt AD uNjBDXM O GtnL D\").split(\" \");" fullword ascii
    $s6  = "lHCQi.open(xefpx,dKQwc,false);" fullword ascii
    $s7  = "if (VJCIK == 523-323){return true;} else {return false;}" fullword ascii
    $s8  = "function DjrL(MkQbR) {" fullword ascii
    $s9  = "function wgtX(Qirwa) {" fullword ascii
    $s10 = "function iDvR(PwjGt) {" fullword ascii
    $s11 = "return QEyt[alsYrp[0]];" fullword ascii
    $s12 = "if (lOzHD > 193888-357){return true;} else {return false;}" fullword ascii
    $s13 = "function ZwYEhGTaN(ZEsUAcuGhnn) {" fullword ascii
    $s14 = "if(K>=Z.length) {break;}" fullword ascii
    $s15 = "return MkQbR.status;" fullword ascii
    $s16 = "function bfbFf(LsSmTW) {" fullword ascii
    $s17 = "return DaFVxID(gR,GHhVA[571-565]+GHhVA[761-754]+GHhVA[429-421]);" fullword ascii
    $s18 = "function mUYK(CBSaC,rcbyC) {" fullword ascii
    $s19 = "function lKGH(TaAwG,hOwRN) {" fullword ascii
    $s20 = "function UcdNIRULv(GZLcW) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}