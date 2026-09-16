rule sig_20160310_f964e907be00d30950f2342a8897cfbc {
  meta:
    description = "datamaliciousorder - file 20160310_f964e907be00d30950f2342a8897cfbc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4ced0f56aa4338b9a791f62c0cef898827b8f2f83993df10b02b46a058c86a7"

  strings:
    $s1  = "var IH = true  , mdtN = pmI[7] + pmI[9] + pmI[11];" fullword ascii
    $s2  = "return VJZJJpB[0] + VJZJJpB[2] + VJZJJpB[4] + \".F\" + VJZJJpB[7] + VJZJJpB[9] + VJZJJpB[12] + VJZJJpB[14];" fullword ascii
    $s3  = "var VJZJJpB = \"Sc qdUPAUh r BCVpaBztm ipting eymLGqU Ywi ile PMOndnzOVjhigs System dg MVSDK Obj mZzZYC ect kIIQBCp\".split(\" " ascii
    $s4  = "QKuzD.open(DKmrP,LWsqk,false);" fullword ascii
    $s5  = "function SvukTanF(LcbWa,NhUdeB) {" fullword ascii
    $s6  = "function DQzGUgW(IsZk) {" fullword ascii
    $s7  = "if(f>=v.length) {break;}" fullword ascii
    $s8  = "return ijkT.ExpandEnvironmentStrings(fHbuN);" fullword ascii
    $s9  = "function acPK(WEuDW) {" fullword ascii
    $s10 = "function hfvZ(dFurH) {" fullword ascii
    $s11 = "return HiXCnMC" fullword ascii
    $s12 = "function reBGhtkmL(pELHI,Fkown,eFMJi,wjGY) {" fullword ascii
    $s13 = "function Xtppp(cIlWuw) {" fullword ascii
    $s14 = "function SlvJ(QKuzD,LWsqk,DKmrP) {" fullword ascii
    $s15 = "return new ActiveXObject(cIlWuw);" fullword ascii
    $s16 = "return jfd.size;" fullword ascii
    $s17 = "function pRsCe(oiUAcD) {" fullword ascii
    $s18 = "function gKqK(SoqIA) {" fullword ascii
    $s19 = "if (SoqIA == 1083-883){return true;} else {return false;}" fullword ascii
    $s20 = "function hxVHZiVx(jfd) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}