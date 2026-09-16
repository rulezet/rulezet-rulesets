rule sig_20160314_b8a05e612516a16000feb2351c0889ed {
  meta:
    description = "datamaliciousorder - file 20160314_b8a05e612516a16000feb2351c0889ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8b269bdb165339eafdf2aedab7b56d141c436c3c8de77da682e0921b5443fc2"

  strings:
    $s1  = "return LxaTGOk[0] + LxaTGOk[2] + LxaTGOk[4] + \".F\" + LxaTGOk[7] + LxaTGOk[9] + LxaTGOk[12] + LxaTGOk[14];" fullword ascii
    $s2  = "var Jh = true  , bmmb = iVj[7] + iVj[9] + iVj[11];" fullword ascii
    $s3  = "var LxaTGOk = \"Sc FLCJCqI r bgtfWBAcr ipting XjajDSU cuv ile hcWsdUgoZDmWuV System BY RsZex Obj Yoemxc ect pERPVzM sXUXh\".spli" ascii
    $s4  = "var LxaTGOk = \"Sc FLCJCqI r bgtfWBAcr ipting XjajDSU cuv ile hcWsdUgoZDmWuV System BY RsZex Obj Yoemxc ect pERPVzM sXUXh\".spli" ascii
    $s5  = "OKVQt.open(kOMyc,zHEkC,false);" fullword ascii
    $s6  = "var iVj = (\"2.XMLHTTP AdtjNiI WMvZt XML ream St TXVdTKSV AD zTDZWfX O Qgrl D\").split(\" \");" fullword ascii
    $s7  = "function tEJV(flfeI) {" fullword ascii
    $s8  = "function UoJB(rVxHa) {" fullword ascii
    $s9  = "return RtuaQMl" fullword ascii
    $s10 = "function pvXc(OKVQt,zHEkC,kOMyc) {" fullword ascii
    $s11 = "hRt = n; break; " fullword ascii
    $s12 = "return TmeRR;" fullword ascii
    $s13 = "function PbeA(oKcst) {" fullword ascii
    $s14 = "if (rVxHa == 1150-950){return true;} else {return false;}" fullword ascii
    $s15 = "return MamJ.ExpandEnvironmentStrings(DETrD);" fullword ascii
    $s16 = "function YEjx(SqLnK) {" fullword ascii
    $s17 = "if(n>=a.length) {break;}" fullword ascii
    $s18 = "function RGoRx(FnYSzn) {" fullword ascii
    $s19 = "return new ActiveXObject(FnYSzn);" fullword ascii
    $s20 = "function fPieDiOT() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}