rule sig_20160322_b60722301cb48e4fa00b7fee226003d1 {
  meta:
    description = "datamaliciousorder - file 20160322_b60722301cb48e4fa00b7fee226003d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db3a4d9c825e10916739de867b4b258cde5727d420e00bb748579f215c1b5170"

  strings:
    $s1  = "return WScript.CreateObject(vFSRB);" fullword ascii
    $s2  = "var pd = true  , dgzr = ZkM[7] + ZkM[9] + ZkM[11];" fullword ascii
    $s3  = "return aEfCtwr[0] + aEfCtwr[2] + aEfCtwr[4] + \".F\" + aEfCtwr[7] + aEfCtwr[9] + aEfCtwr[12] + aEfCtwr[14];" fullword ascii
    $s4  = "rGjU.open(WlGTn,xVbwF,false);" fullword ascii
    $s5  = "var aEfCtwr = hhDhc(GrirFUZGSs+\" \"+\"System jk zAqDF Obj beGgRX ect VlSvMYj yxUqx\", \" \");" fullword ascii
    $s6  = "if(w>=h.length) {break;}" fullword ascii
    $s7  = "function UdDa(FvwHa,lwvPG) {" fullword ascii
    $s8  = "function TDTo(YTLrW,OcuBk) {" fullword ascii
    $s9  = "function RvyUtSrg(Ddix) {" fullword ascii
    $s10 = "function Urmq(GWxBU) {" fullword ascii
    $s11 = "function NriW(NSpOg) {" fullword ascii
    $s12 = "function misA(LYrrn) {" fullword ascii
    $s13 = "if (sfnhv == 897-697){return true;} else {return false;}" fullword ascii
    $s14 = "return wMrU[QEfpob[0]];" fullword ascii
    $s15 = "if (aamTE > 197359-843){return true;} else {return false;}" fullword ascii
    $s16 = "return RjgXfr.position=565-565;" fullword ascii
    $s17 = "function wunkRkL(wMrU) {" fullword ascii
    $s18 = "function yjDtZ(MZzNIi) {" fullword ascii
    $s19 = "function pjbjDwMXL(cSEZm) {" fullword ascii
    $s20 = "function VZZr(vFSRB) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}