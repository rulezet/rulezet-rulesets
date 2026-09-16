rule sig_20160321_738a8d0bb4e0ef1068c4e9fa9f3d696a {
  meta:
    description = "datamaliciousorder - file 20160321_738a8d0bb4e0ef1068c4e9fa9f3d696a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2caede258631c465a333abc143b05dfeb63dd6bbb74754bd593eac2a2102a2de"

  strings:
    $s1  = "return WScript.CreateObject(RZjfa);" fullword ascii
    $s2  = "var Nt = true  , HYFj = ytT[7] + ytT[9] + ytT[11];" fullword ascii
    $s3  = "return xJoETbR[0] + xJoETbR[2] + xJoETbR[4] + \".F\" + xJoETbR[7] + xJoETbR[9] + xJoETbR[12] + xJoETbR[14];" fullword ascii
    $s4  = "var xJoETbR = DQEKK(wMjjDGqAhq+\" \"+\"System hj rLGeB Obj vAmXMf ect FwwYeff QrcQa\", \" \");" fullword ascii
    $s5  = "FalIv.open(YzHSs,HRusY,false);" fullword ascii
    $s6  = "var ytT = (\"2.XMLHTTP NzViwqP CuzAs XML ream St ZgjDuzGT AD YePqgdR O mfng D\").split(\" \");" fullword ascii
    $s7  = "function Ukcj(CekyZ,AaTYC) {" fullword ascii
    $s8  = "function kOvC(aOvHc) {" fullword ascii
    $s9  = "return iObbVu.position=621-621;" fullword ascii
    $s10 = "return Edj.split(DqCua);" fullword ascii
    $s11 = "function jXft(RZjfa) {" fullword ascii
    $s12 = "function OeWZ(ytoqF,tbVnb) {" fullword ascii
    $s13 = "if(F>=u.length) {break;}" fullword ascii
    $s14 = "function aPUl(vxMGy) {" fullword ascii
    $s15 = "function VkJc(mnJAB) {" fullword ascii
    $s16 = "function DQEKK(Edj,DqCua) {" fullword ascii
    $s17 = "function chhhZff(FqNG,XTgNR) {" fullword ascii
    $s18 = "function bTGQvQNa(XMFA) {" fullword ascii
    $s19 = "function tOwT(ZRFkK) {" fullword ascii
    $s20 = "function DKqp(FalIv,HRusY,YzHSs) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}