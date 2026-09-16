rule sig_20160309_d436a1f939db9b365c11f2aa084c9c9d {
  meta:
    description = "datamaliciousorder - file 20160309_d436a1f939db9b365c11f2aa084c9c9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d57dee79ad635bf6e517da9edb19b399badeacc3bd243f24aec82977649773c7"

  strings:
    $s1  = "var ODL = (\"2.XMLHTTP meSPyGi kJntJ XML ream St VJooiYvc AD OGEdPPx O hxOx D\").split(\" \");" fullword ascii
    $s2  = "return EImwBzC[0] + EImwBzC[2] + EImwBzC[4] + \".F\" + EImwBzC[7] + EImwBzC[9] + EImwBzC[12] + EImwBzC[14];" fullword ascii
    $s3  = "var qz = true  , vMDW = ODL[7] + ODL[9] + ODL[11];" fullword ascii
    $s4  = "NBTKO.open(DRGGy,SfeOY,false);" fullword ascii
    $s5  = "var EImwBzC = \"Sc XpXYfTt r fZADHeObH ipting xzUBwlq baI ile rRnsiDcDsIQfKQ System zc jdaIc Obj KacwTX ect zcbgWch\".split(\" " ascii
    $s6  = "function WpOp(ryEew) {" fullword ascii
    $s7  = "function EhOb(liuev) {" fullword ascii
    $s8  = "mUU = m; break; " fullword ascii
    $s9  = "if(m>=C.length) {break;}" fullword ascii
    $s10 = "return Fd.ExpandEnvironmentStrings(vTRjh[6]+vTRjh[7]+vTRjh[8]);" fullword ascii
    $s11 = "function YIYSjRMup(NWKVickZkmI) {" fullword ascii
    $s12 = "function UKyXIbF(MTbL) {" fullword ascii
    $s13 = "return OqXjV;" fullword ascii
    $s14 = "function jZNp(AjEpr,mgGFL) {" fullword ascii
    $s15 = "function NZeC(raCRn,DTCuT) {" fullword ascii
    $s16 = "return gMBTQzV" fullword ascii
    $s17 = "return new ActiveXObject(BbaJaK);" fullword ascii
    $s18 = "function qKQY(RdLJU) {" fullword ascii
    $s19 = "function SkNkhayj() {" fullword ascii
    $s20 = "if (ryEew > 195533-950){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}