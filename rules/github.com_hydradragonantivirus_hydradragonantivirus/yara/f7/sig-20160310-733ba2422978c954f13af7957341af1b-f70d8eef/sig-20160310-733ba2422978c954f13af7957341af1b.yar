rule sig_20160310_733ba2422978c954f13af7957341af1b {
  meta:
    description = "datamaliciousorder - file 20160310_733ba2422978c954f13af7957341af1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c10d14a4898303d3e16d768efe27cb67721a828aacac12915c62d71b31a1911"

  strings:
    $s1  = "var gZ = true  , rZIp = zWo[7] + zWo[9] + zWo[11];" fullword ascii
    $s2  = "return rjEhRgv[0] + rjEhRgv[2] + rjEhRgv[4] + \".F\" + rjEhRgv[7] + rjEhRgv[9] + rjEhRgv[12] + rjEhRgv[14];" fullword ascii
    $s3  = "iwHes.open(BYezo,ZSdjx,false);" fullword ascii
    $s4  = "var zWo = (\"2.XMLHTTP qzJdlwm IdYRg XML ream St rCKpLfJu AD KrIZoDX O ggNG D\").split(\" \");" fullword ascii
    $s5  = "var rjEhRgv = \"Sc iuFuHQx r evJKbCemQ ipting mRVmFcN Vam ile XCpJzWdQPpCVfw System Ok MGlJr Obj AhHauX ect hwqbxcv\".split(\" " ascii
    $s6  = "function vXCJ(BCpwO) {" fullword ascii
    $s7  = "return Cfgq.ExpandEnvironmentStrings(CysKC);" fullword ascii
    $s8  = "if (SYqxB > 199391-693){return true;} else {return false;}" fullword ascii
    $s9  = "return xowXE.status;" fullword ascii
    $s10 = "function zDyHltjO() {" fullword ascii
    $s11 = "function qWGDG(RzAyxo) {" fullword ascii
    $s12 = "if (Q >= BCpwO.length) {break;}" fullword ascii
    $s13 = "function pJlhR(QUEjgc) {" fullword ascii
    $s14 = "function KQoq(iwHes,ZSdjx,BYezo) {" fullword ascii
    $s15 = "return WPqc.responseBody;" fullword ascii
    $s16 = "return xuE.size;" fullword ascii
    $s17 = "function uLVe(TvVuS) {" fullword ascii
    $s18 = "function iZuY(Nuuyl) {" fullword ascii
    $s19 = "return cLIYWjy" fullword ascii
    $s20 = "function UVZL(VdciV,bvpsg) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}