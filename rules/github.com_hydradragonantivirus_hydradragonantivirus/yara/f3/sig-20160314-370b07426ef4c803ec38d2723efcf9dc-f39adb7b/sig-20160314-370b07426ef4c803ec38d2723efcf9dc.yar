rule sig_20160314_370b07426ef4c803ec38d2723efcf9dc {
  meta:
    description = "datamaliciousorder - file 20160314_370b07426ef4c803ec38d2723efcf9dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ff7a70537925b5ad6b9a15b0999e554452bb014d736a5913a1457beb4c10e60"

  strings:
    $s1  = "var Iu = true  , JiOZ = vYh[7] + vYh[9] + vYh[11];" fullword ascii
    $s2  = "return xPOsZZO[0] + xPOsZZO[2] + xPOsZZO[4] + \".F\" + xPOsZZO[7] + xPOsZZO[9] + xPOsZZO[12] + xPOsZZO[14];" fullword ascii
    $s3  = "var vYh = (\"2.XMLHTTP rXRYSUx RBtmN XML ream St BAvySVTJ AD yWsxnsx O ttkA D\").split(\" \");" fullword ascii
    $s4  = "obFMp.open(vmUXu,JfwXs,false);" fullword ascii
    $s5  = "var xPOsZZO = DVDNE(\"Sc BzOGPOa r pxHRGugPd ipting urktRvt hxd ile NxDBIaveBlzUHn System hG sCzty Obj UaBQwN ect SZewIcd AsjIB" ascii
    $s6  = "var xPOsZZO = DVDNE(\"Sc BzOGPOa r pxHRGugPd ipting urktRvt hxd ile NxDBIaveBlzUHn System hG sCzty Obj UaBQwN ect SZewIcd AsjIB" ascii
    $s7  = "function vmJL(uCyCJ) {" fullword ascii
    $s8  = "function QAto(LxghK) {" fullword ascii
    $s9  = "function nFgT(tILxU) {" fullword ascii
    $s10 = "function NpKrtEfpv(dvGQGhaUjIu) {" fullword ascii
    $s11 = "return RHCDF;" fullword ascii
    $s12 = "function wfAM(cNwld) {" fullword ascii
    $s13 = "return ZZr.size;" fullword ascii
    $s14 = "function jFno(LlOFu,BYxWd) {" fullword ascii
    $s15 = "function qyDj(obFMp,JfwXs,vmUXu) {" fullword ascii
    $s16 = "if (M >= PfSma.length) {break;}" fullword ascii
    $s17 = "return tZiDVS.position=383-383;" fullword ascii
    $s18 = "if (Ugcut == 764-564){return true;} else {return false;}" fullword ascii
    $s19 = "return RJIeyDj" fullword ascii
    $s20 = "return xHL.split(TJVwY);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}