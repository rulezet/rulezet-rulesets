rule sig_20160405_4c954d056113ac713d4895c0a54635d9 {
  meta:
    description = "datamaliciousorder - file 20160405_4c954d056113ac713d4895c0a54635d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8eb5777ccfbb3ba40b2f59237f4bb24caf676c33ea4afb3b3146bbdb66c4221"

  strings:
    $s1  = "var OF = true  , iGur = QNW[7] + QNW[9] + QNW[11];" fullword ascii
    $s2  = "return DiuJuwD[0] + DiuJuwD[2] + DiuJuwD[4] + \".F\" + DiuJuwD[7] + DiuJuwD[9] + DiuJuwD[12] + DiuJuwD[14];" fullword ascii
    $s3  = "var QNW = (\"2.XMLHTTP EmljKiO httCY XML ream St YtWGgrxD AD yLomwuY O mWiJ D\").split(\" \");" fullword ascii
    $s4  = "gglM.open(JSdac,gMnKP,false);" fullword ascii
    $s5  = "function xszux(yWqnCR) {" fullword ascii
    $s6  = "function CCoVLU(iQxhPDM) {" fullword ascii
    $s7  = "return olkz;" fullword ascii
    $s8  = "function Ghoc(VkVhA,gMnKP,JSdac) {" fullword ascii
    $s9  = "function tUZbSaxLa(BaHFX) {" fullword ascii
    $s10 = "function RDBeJF(JsCi,WMCpkx) {" fullword ascii
    $s11 = "return iHKkBWv[0];" fullword ascii
    $s12 = "return ihH.split(olvFX);" fullword ascii
    $s13 = "function CzLwH(NBmusEdg,VTbb) {" fullword ascii
    $s14 = "if (jcTjq > 153144-611){return true;} else {return false;}" fullword ascii
    $s15 = "return new ActiveXObject(MGJc);" fullword ascii
    $s16 = "function vBvEBVMMF(ZsVgDHcZhLg) {" fullword ascii
    $s17 = "function fOZI(AzNBE) {" fullword ascii
    $s18 = "function myLi(DNLMX) {" fullword ascii
    $s19 = "if(b>=M.length) {break;}" fullword ascii
    $s20 = "if (DNLMX == 930-730){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}