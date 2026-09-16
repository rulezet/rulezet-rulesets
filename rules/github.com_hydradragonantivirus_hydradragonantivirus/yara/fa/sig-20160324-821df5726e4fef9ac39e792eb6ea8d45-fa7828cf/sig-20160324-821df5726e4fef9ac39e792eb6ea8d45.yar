rule sig_20160324_821df5726e4fef9ac39e792eb6ea8d45 {
  meta:
    description = "datamaliciousorder - file 20160324_821df5726e4fef9ac39e792eb6ea8d45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd5106ae0d846972786b88a70c5c6c29cccfc7b057120eff148a4c6fdf471d68"

  strings:
    $s1  = "return WScript.CreateObject(stPGS);" fullword ascii
    $s2  = "return yiVvnZu[0] + yiVvnZu[2] + yiVvnZu[4] + \".F\" + yiVvnZu[7] + yiVvnZu[9] + yiVvnZu[12] + yiVvnZu[14];" fullword ascii
    $s3  = "var Am = true  , VVFJ = UmC[7] + UmC[9] + UmC[11];" fullword ascii
    $s4  = "var UmC = (\"2.XMLHTTP UGWgOJW nNZox XML ream St gbOladfn AD DcIxxae O ZncL D\").split(\" \");" fullword ascii
    $s5  = "var yiVvnZu = SulVB(SBIBKGEQkO+\" \"+\"System Ni EhgvK Obj mxRRfM ect czEZneO nzyhM\", \" \");" fullword ascii
    $s6  = "pJYL.open(BRquR,WGUhq,false);" fullword ascii
    $s7  = "function QpVl(wamBJ,WGUhq,BRquR) {" fullword ascii
    $s8  = "function ORwU(BwmRH) {" fullword ascii
    $s9  = "if (K >= KMDpd.length) {break;}" fullword ascii
    $s10 = "return YavPMkD(GN,ZlVme[446-440]+ZlVme[675-668]+ZlVme[222-214]);" fullword ascii
    $s11 = "if (pQkxk == 879-679){return true;} else {return false;}" fullword ascii
    $s12 = "function OnRWZ(MhddHa) {" fullword ascii
    $s13 = "return new ActiveXObject(JYvj);" fullword ascii
    $s14 = "function haJPCTlr(uaq) {" fullword ascii
    $s15 = "function FYMY(zzKbY,CEdVD) {" fullword ascii
    $s16 = "return uaq.size;" fullword ascii
    $s17 = "function jyfJ(pkqbD) {" fullword ascii
    $s18 = "function qDUdI(jYpWRSCl,Alqc) {" fullword ascii
    $s19 = "function YavPMkD(XYyD,VSaxi) {" fullword ascii
    $s20 = "function VItPhlhM(MllF) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}