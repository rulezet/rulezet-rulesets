rule sig_20160321_73c11176aa67a829aea8a5af06399e37 {
  meta:
    description = "datamaliciousorder - file 20160321_73c11176aa67a829aea8a5af06399e37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "650b3f88fc1adffa062058d5634c71ec97aae30a4b725183bab0b18bb9961ec1"

  strings:
    $s1  = "return WScript.CreateObject(ZgwrL);" fullword ascii
    $s2  = "var XA = true  , KlDP = FBR[7] + FBR[9] + FBR[11];" fullword ascii
    $s3  = "return lRenHng[0] + lRenHng[2] + lRenHng[4] + \".F\" + lRenHng[7] + lRenHng[9] + lRenHng[12] + lRenHng[14];" fullword ascii
    $s4  = "var FBR = (\"2.XMLHTTP VblOMvX ukXiD XML ream St qIVzXlZJ AD bNJHRJH O CZlf D\").split(\" \");" fullword ascii
    $s5  = "var lRenHng = TmGIB(ySzLxVaMPf+\" \"+\"System jI taJex Obj CuxTnx ect EqCCPNW CbGUP\", \" \");" fullword ascii
    $s6  = "YrYMi.open(YZzFW,RargI,false);" fullword ascii
    $s7  = "function HPekEVcQa(MKyhB) {" fullword ascii
    $s8  = "GrD = D; break; " fullword ascii
    $s9  = "function EhFz(KteWj) {" fullword ascii
    $s10 = "return KteWj.status;" fullword ascii
    $s11 = "function CjoKI(wSVCEX) {" fullword ascii
    $s12 = "function opLu(YrYMi,RargI,YZzFW) {" fullword ascii
    $s13 = "function TmGIB(THK,JaBjW) {" fullword ascii
    $s14 = "return VTHm.ExpandEnvironmentStrings(GVsGa);" fullword ascii
    $s15 = "function UZXe(GNhfT) {" fullword ascii
    $s16 = "function Wcid(rmaPS,NApax) {" fullword ascii
    $s17 = "function ukXnVZClG(EymaNSHoWTl) {" fullword ascii
    $s18 = "function fVwPmJFo(Jnx) {" fullword ascii
    $s19 = "return new ActiveXObject(wSVCEX);" fullword ascii
    $s20 = "function NNJFL(CEeSds) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}