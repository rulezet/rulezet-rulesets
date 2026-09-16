rule sig_20160314_927bc11da88e41f0af8b89fd7e098875 {
  meta:
    description = "datamaliciousorder - file 20160314_927bc11da88e41f0af8b89fd7e098875.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "229487802c1af570fcc2e47fcd77f989749f3a204f08edce1c04b70fa6e55666"

  strings:
    $s1  = "var kC = true  , Iwsq = yeh[7] + yeh[9] + yeh[11];" fullword ascii
    $s2  = "return BrNruAf[0] + BrNruAf[2] + BrNruAf[4] + \".F\" + BrNruAf[7] + BrNruAf[9] + BrNruAf[12] + BrNruAf[14];" fullword ascii
    $s3  = "vdycW.open(wOFeJ,PmEFr,false);" fullword ascii
    $s4  = "var BrNruAf = \"Sc FdKsvwq r enmEUTeRZ ipting kJTQaiB suA ile sjqtylXSVyeLUN System Bc cTyqe Obj QfQeSi ect gNjJNWA STuxo\".spli" ascii
    $s5  = "var BrNruAf = \"Sc FdKsvwq r enmEUTeRZ ipting kJTQaiB suA ile sjqtylXSVyeLUN System Bc cTyqe Obj QfQeSi ect gNjJNWA STuxo\".spli" ascii
    $s6  = "var yeh = (\"2.XMLHTTP vWezyZp HFMKb XML ream St fZCmEqnc AD alFaOeo O QZrq D\").split(\" \");" fullword ascii
    $s7  = "function pWkGeQCtl(agvYLMIdEqm) {" fullword ascii
    $s8  = "return LdvQjy.position=895-895;" fullword ascii
    $s9  = "return CbMe.responseBody;" fullword ascii
    $s10 = "return uqwxI.status;" fullword ascii
    $s11 = "function ZhfJ(PAAsd) {" fullword ascii
    $s12 = "function VrWq(UPtaV) {" fullword ascii
    $s13 = "return NVR.size;" fullword ascii
    $s14 = "if (zyFVH > 177730-341){return true;} else {return false;}" fullword ascii
    $s15 = "return new ActiveXObject(oFzYuh);" fullword ascii
    $s16 = "return kaxN.ExpandEnvironmentStrings(CLmXs);" fullword ascii
    $s17 = "AEr = y; break; " fullword ascii
    $s18 = "function qsoNqeA(kaxN,CLmXs) {" fullword ascii
    $s19 = "if(y>=G.length) {break;}" fullword ascii
    $s20 = "function odGAK(LdvQjy) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}