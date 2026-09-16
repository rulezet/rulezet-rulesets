rule sig_20160307_6250180aa3acb4d62de8a3f3603198cb {
  meta:
    description = "datamaliciousorder - file 20160307_6250180aa3acb4d62de8a3f3603198cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57ab89f13fa78144fd5b5afd0d1f1e2813fdb72252fc7ccec22f37f4f9311ffa"

  strings:
    $s1  = "return uwbJnEf[0] + uwbJnEf[2] + uwbJnEf[4] + \".F\" + uwbJnEf[7] + uwbJnEf[9] + uwbJnEf[12] + uwbJnEf[14];" fullword ascii
    $s2  = "var ja = true  , XqMx = Tiw[7] + Tiw[9] + Tiw[11];" fullword ascii
    $s3  = "var uwbJnEf = \"Sc ZUspcZA r JsbHeFaQh ipting lyLcgwr uAT ile vnLOEBiVfmMggE System Nz nyvcG Obj uowauF ect jfTWXag\".split(\" " ascii
    $s4  = "var Tiw = (\"2.XMLHTTP jdkrhci uduOM XML ream St jGvZbyhp AD lsJzkDI O ypSi D\").split(\" \");" fullword ascii
    $s5  = "tBOeI.open(TOjKu,ZPwER,false);" fullword ascii
    $s6  = "return zBcQp;" fullword ascii
    $s7  = "function wRvLfoASA(yjHHK,erEIh,NYTUd,aPcG) {" fullword ascii
    $s8  = "function hSyB(EbBem) {" fullword ascii
    $s9  = "function ABAgSqgv() {" fullword ascii
    $s10 = "return tD.ExpandEnvironmentStrings(PIwCw[6]+PIwCw[7]+PIwCw[8]);" fullword ascii
    $s11 = "if(T>=f.length) {break;}" fullword ascii
    $s12 = "function fYVH(uWOZU) {" fullword ascii
    $s13 = "function Isbm(GryxD) {" fullword ascii
    $s14 = "function WDxhibQma(WkSYmFIzSxC) {" fullword ascii
    $s15 = "return vHDm.responseBody;" fullword ascii
    $s16 = "function xckzToas(UzN) {" fullword ascii
    $s17 = "function qcns(tBOeI,ZPwER,TOjKu) {" fullword ascii
    $s18 = "if (FVGUF == 357-157){return true;} else {return false;}" fullword ascii
    $s19 = "return UzN.size;" fullword ascii
    $s20 = "function BnPX(NaxtM,sFkLP) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}