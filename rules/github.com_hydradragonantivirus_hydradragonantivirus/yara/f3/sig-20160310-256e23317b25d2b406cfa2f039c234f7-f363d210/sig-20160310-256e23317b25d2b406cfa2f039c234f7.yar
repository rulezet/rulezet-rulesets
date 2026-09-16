rule sig_20160310_256e23317b25d2b406cfa2f039c234f7 {
  meta:
    description = "datamaliciousorder - file 20160310_256e23317b25d2b406cfa2f039c234f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "297fd42365fb3fa05ebe2fbf599f3b8bbab72b23b372c8d0a23343e3185ef727"

  strings:
    $s1  = "var Kf = true  , IQUE = SPk[7] + SPk[9] + SPk[11];" fullword ascii
    $s2  = "return FCxAOXp[0] + FCxAOXp[2] + FCxAOXp[4] + \".F\" + FCxAOXp[7] + FCxAOXp[9] + FCxAOXp[12] + FCxAOXp[14];" fullword ascii
    $s3  = "kYGvD.open(EWlrT,yukjP,false);" fullword ascii
    $s4  = "var FCxAOXp = \"Sc IvNUwlE r aCMuDQyxS ipting FeTRBIs ihz ile yiBICIzxeHgTJE System Du RsNWe Obj HVvlSA ect iPhESUU\".split(\" " ascii
    $s5  = "var SPk = (\"2.XMLHTTP rOjLOHs iHdkY XML ream St AMXPOSoq AD NcfcKxV O pQOj D\").split(\" \");" fullword ascii
    $s6  = "function bEXxs(JHkJWb) {" fullword ascii
    $s7  = "if (lCFOl > 192817-906){return true;} else {return false;}" fullword ascii
    $s8  = "qTW = h; break; " fullword ascii
    $s9  = "return uVPjzQ.position=807-807;" fullword ascii
    $s10 = "if (I >= mghgI.length) {break;}" fullword ascii
    $s11 = "return TcBw.ExpandEnvironmentStrings(bBKem);" fullword ascii
    $s12 = "function VBXU(KjwSG) {" fullword ascii
    $s13 = "function sfCG(bLaFC,IqhBP) {" fullword ascii
    $s14 = "if(h>=Y.length) {break;}" fullword ascii
    $s15 = "function tJDA(tKwiO,eolYi) {" fullword ascii
    $s16 = "function yLFjkevAv(pQiNwjOJYfW) {" fullword ascii
    $s17 = "return BPHAXaE" fullword ascii
    $s18 = "return yHkrbzM(px,ZfWXQ[946-940]+ZfWXQ[349-342]+ZfWXQ[234-226]);" fullword ascii
    $s19 = "function Yxxv(BsFkU) {" fullword ascii
    $s20 = "function xjMu(mghgI) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}