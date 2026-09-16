rule sig_20160321_11fa2e12ba63fbf2f11a57860901a65e {
  meta:
    description = "datamaliciousorder - file 20160321_11fa2e12ba63fbf2f11a57860901a65e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e90d4171c7c2d44f0f5742caad7f193281e74b63fb1e536af989b1be566e2e15"

  strings:
    $s1  = "return WScript.CreateObject(BdKWP);" fullword ascii
    $s2  = "return tSKQPuQ[0] + tSKQPuQ[2] + tSKQPuQ[4] + \".F\" + tSKQPuQ[7] + tSKQPuQ[9] + tSKQPuQ[12] + tSKQPuQ[14];" fullword ascii
    $s3  = "var cL = true  , PkQF = ZgF[7] + ZgF[9] + ZgF[11];" fullword ascii
    $s4  = "otxpP.open(zpzBc,ZuzgB,false);" fullword ascii
    $s5  = "var ZgF = (\"2.XMLHTTP deUOhHU VlFHU XML ream St SbBJANDU AD NJUkTtb O dcnp D\").split(\" \");" fullword ascii
    $s6  = "var tSKQPuQ = Azrtl(NeRkDBrQpP+\" \"+\"System Qd xztya Obj ukpSSQ ect RojRSpJ kQBoi\", \" \");" fullword ascii
    $s7  = "function yIfwCiniB(aOtOP) {" fullword ascii
    $s8  = "function oVaOJHYYO(nCZCeeZIXeo) {" fullword ascii
    $s9  = "function YgEg(opVZz,PKndb) {" fullword ascii
    $s10 = "return ellYpD.position=419-419;" fullword ascii
    $s11 = "return COgIT.status;" fullword ascii
    $s12 = "if (fvxbi > 186758-426){return true;} else {return false;}" fullword ascii
    $s13 = "if(R>=S.length) {break;}" fullword ascii
    $s14 = "if (IaqJs == 575-375){return true;} else {return false;}" fullword ascii
    $s15 = "if (y >= zmwme.length) {break;}" fullword ascii
    $s16 = "dAz = R; break; " fullword ascii
    $s17 = "return lYtRhTh(ib,SSPBY[113-107]+SSPBY[118-111]+SSPBY[704-696]);" fullword ascii
    $s18 = "function JhlO(IaqJs) {" fullword ascii
    $s19 = "return bfr.size;" fullword ascii
    $s20 = "return lKhOS;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}