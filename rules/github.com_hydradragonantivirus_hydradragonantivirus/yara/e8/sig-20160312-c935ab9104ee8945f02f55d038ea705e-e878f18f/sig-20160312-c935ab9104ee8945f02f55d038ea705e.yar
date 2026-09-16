rule sig_20160312_c935ab9104ee8945f02f55d038ea705e {
  meta:
    description = "datamaliciousorder - file 20160312_c935ab9104ee8945f02f55d038ea705e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29720bf77592e87b9d5dd404f73b273c1abde51a8845f003a5f5371cfc6e7492"

  strings:
    $s1  = "var Es = true  , oMEk = vil[7] + vil[9] + vil[11];" fullword ascii
    $s2  = "return vTxKVhj[0] + vTxKVhj[2] + vTxKVhj[4] + \".F\" + vTxKVhj[7] + vTxKVhj[9] + vTxKVhj[12] + vTxKVhj[14];" fullword ascii
    $s3  = "var vil = (\"2.XMLHTTP tinYhuv xGLnN XML ream St QJiJjTKM AD hKqgLtS O xpaS D\").split(\" \");" fullword ascii
    $s4  = "var vTxKVhj = \"Sc paHObzs r MTlAqEjrX ipting MdMqYWl uSI ile VVFNYZORGfIhrW System HI aLHbS Obj OvUbPQ ect VsNlRsS\".split(\" " ascii
    $s5  = "qAgWE.open(QdrIg,YBfct,false);" fullword ascii
    $s6  = "return LsqZ.ExpandEnvironmentStrings(nlyrz);" fullword ascii
    $s7  = "function HdxriaXET(dcSIyhYoCRQ) {" fullword ascii
    $s8  = "return new ActiveXObject(hlJtcl);" fullword ascii
    $s9  = "function aimI(PpwZw) {" fullword ascii
    $s10 = "function KPDXYvXcV() {" fullword ascii
    $s11 = "function hmxi(VwFoh,eETOF) {" fullword ascii
    $s12 = "function mzyP(qAgWE,YBfct,QdrIg) {" fullword ascii
    $s13 = "var QOZWYWqq = (\"FAfF!Ws!TNOIBdL!c!ecHahE!ri\"+\"!pt!KpnbCsHS!.S!cnOiJ!he!KrFTRu!ll!zLBjYQH!DpnLvrzL\").split(\"!\");" fullword ascii
    $s14 = "return sVhhtDa(HK,UTFRY[422-416]+UTFRY[742-735]+UTFRY[470-462]);" fullword ascii
    $s15 = "return xslgCqi" fullword ascii
    $s16 = "function KOABtZv(MzTw) {" fullword ascii
    $s17 = "function btwNv(ENrpcm) {" fullword ascii
    $s18 = "if (v >= oNcJY.length) {break;}" fullword ascii
    $s19 = "function YEkaS(hlJtcl) {" fullword ascii
    $s20 = "return PpwZw.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}