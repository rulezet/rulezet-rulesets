rule sig_20160307_6ad7043406de9d699184396a310e2db2 {
  meta:
    description = "datamaliciousorder - file 20160307_6ad7043406de9d699184396a310e2db2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d2be89e45d82abf732fbf494f6dc4af310e825241c833814013f1f8939b89a5"

  strings:
    $s1  = "var PR = true  , GNQX = nhV[7] + nhV[9] + nhV[11];" fullword ascii
    $s2  = "return hyKtHMY[0] + hyKtHMY[2] + hyKtHMY[4] + \".F\" + hyKtHMY[7] + hyKtHMY[9] + hyKtHMY[12] + hyKtHMY[14];" fullword ascii
    $s3  = "FAXxm.open(RNERh,hzEHo,false);" fullword ascii
    $s4  = "var nhV = (\"2.XMLHTTP NdvGEjt dmdLx XML ream St uRUAhiRk AD CXXyfGs O bXwt D\").split(\" \");" fullword ascii
    $s5  = "var hyKtHMY = \"Sc pvfKYhB r zraBcHZEq ipting zsSiOIz fve ile QzjDMGiZzygTVr System qq lfaqM Obj HqOARv ect xaKakjp\".split(\" " ascii
    $s6  = "rAf.CreateFolder(odOr);" fullword ascii
    $s7  = "return BEN.size;" fullword ascii
    $s8  = "if (YyYLi > 197873-526){return true;} else {return false;}" fullword ascii
    $s9  = "function IToYugSO(BEN) {" fullword ascii
    $s10 = "return tdia.responseBody;" fullword ascii
    $s11 = "function pAFWjYH(tdia) {" fullword ascii
    $s12 = "function kHJS(NErpF) {" fullword ascii
    $s13 = "function JryAFJZS() {" fullword ascii
    $s14 = "function AStm(AqeDW,dKfQU) {" fullword ascii
    $s15 = "function mjbL(YyYLi) {" fullword ascii
    $s16 = "function IBnd(vmfpt,LJTjX) {" fullword ascii
    $s17 = "function AEuT(usSGW) {" fullword ascii
    $s18 = "return fx.ExpandEnvironmentStrings(hfsXe[6]+hfsXe[7]+hfsXe[8]);" fullword ascii
    $s19 = "function uHOm(fCoXM) {" fullword ascii
    $s20 = "function KPdE(sBJxq) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}