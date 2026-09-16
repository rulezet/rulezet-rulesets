rule sig_20160301_01cf104d7b39fd088ccea85fd9ea00ff {
  meta:
    description = "datamaliciousorder - file 20160301_01cf104d7b39fd088ccea85fd9ea00ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b62e5af1588f736a572d65d30166e3d352eeba183ddca1ad586d05b805891e51"

  strings:
    $s1  = "var UG = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(sUzmt);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + HFWPWqp + \".F\" + LKsVFqysDi + HdaHA + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var VZf = (Mix + \"TTP\" + \" REaGFzo yggzT XML ream St hogVGOHC AD bEPBVBe OD\").split(\" \");" fullword ascii
    $s5  = "var JT = true  , EXZu = VZf[7] + \"\" + VZf[9];" fullword ascii
    $s6  = "Axjyp.open(xwXIt,ahHQF,false);" fullword ascii
    $s7  = "function bBfGY(thNiKK) {" fullword ascii
    $s8  = "function ljTC(Axjyp,ahHQF,xwXIt) {" fullword ascii
    $s9  = "return eA.ExpandEnvironmentStrings(UG);" fullword ascii
    $s10 = "function ytdo(ELcLb) {" fullword ascii
    $s11 = "function qeLC(GkOnv) {" fullword ascii
    $s12 = "function ZhCN(vhMtl,fNCyv) {" fullword ascii
    $s13 = "if(S>=g.length) {break;}" fullword ascii
    $s14 = "function kmCg(owFZw,drrRx) {" fullword ascii
    $s15 = "AHb = S; break; " fullword ascii
    $s16 = "function pqyY(ouyRK) {" fullword ascii
    $s17 = "return fiDUY;" fullword ascii
    $s18 = "return GkOnv.status;" fullword ascii
    $s19 = "function CMaB(RABsJ) {" fullword ascii
    $s20 = "if (ouyRK == 733-533){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}