rule sig_20160312_2af2b27aa3fe87f2c3a78c93d444fb74 {
  meta:
    description = "datamaliciousorder - file 20160312_2af2b27aa3fe87f2c3a78c93d444fb74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19fb961b33e6a5ddf77502a1676709ec854398084360b44404d60da3ce0ac4ff"

  strings:
    $s1  = "return KVsnhHs[0] + KVsnhHs[2] + KVsnhHs[4] + \".F\" + KVsnhHs[7] + KVsnhHs[9] + KVsnhHs[12] + KVsnhHs[14];" fullword ascii
    $s2  = "var Oq = true  , tjnL = yDo[7] + yDo[9] + yDo[11];" fullword ascii
    $s3  = "var KVsnhHs = \"Sc zsEoZgM r PqDoNTZBo ipting KAKXjLA ojN ile GftfJYOBzDogYU System jl MVHTE Obj PVLiIg ect fBjTeBD\".split(\" " ascii
    $s4  = "fBSUG.open(qibpf,CWjXC,false);" fullword ascii
    $s5  = "var yDo = (\"2.XMLHTTP UzOIxjm iQjUg XML ream St sFKwNPwA AD ggPAota O BJPb D\").split(\" \");" fullword ascii
    $s6  = "if (z >= EOZfI.length) {break;}" fullword ascii
    $s7  = "function Xumd(lehxK,jYBSi) {" fullword ascii
    $s8  = "return DZaeNLx" fullword ascii
    $s9  = "if (RSwMK > 197230-172){return true;} else {return false;}" fullword ascii
    $s10 = "return Fov.size;" fullword ascii
    $s11 = "return pCFOA;" fullword ascii
    $s12 = "function hmDJyIU(ZEkw) {" fullword ascii
    $s13 = "if(p>=d.length) {break;}" fullword ascii
    $s14 = "function Bgrr(UJTfc) {" fullword ascii
    $s15 = "function HsBkZ(BLIQeB) {" fullword ascii
    $s16 = "return RwTi.ExpandEnvironmentStrings(oPMLG);" fullword ascii
    $s17 = "function NnGr(RSwMK) {" fullword ascii
    $s18 = "function OJRcXlt(RwTi,oPMLG) {" fullword ascii
    $s19 = "return OJRcXlt(md,jhxgz[984-978]+jhxgz[255-248]+jhxgz[814-806]);" fullword ascii
    $s20 = "function ZXcu(fBSUG,CWjXC,qibpf) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}